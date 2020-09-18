#!/usr/bin/env python3

# Copyright 2020 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Charm for deploying and maintaining the Ceph iSCSI service."""

import copy
import socket
import logging
import os
import subprocess
import sys
import string
import secrets
from pathlib import Path

sys.path.append('lib')

from ops.framework import (
    StoredState,
)
from ops.main import main
import ops.model
import charmhelpers.core.host as ch_host
import charmhelpers.core.templating as ch_templating
import interface_ceph_client.ceph_client as ceph_client
import interface_ceph_iscsi_peer
import interface_tls_certificates.ca_client as ca_client

import ops_openstack.adapters
import ops_openstack.core
import gwcli_client
import cryptography.hazmat.primitives.serialization as serialization
logger = logging.getLogger(__name__)


class CephClientAdapter(ops_openstack.adapters.OpenStackOperRelationAdapter):
    """Adapter for ceph client interface."""

    @property
    def mon_hosts(self):
        """Sorted list of ceph mon addresses.

        :returns: Ceph MON addresses.
        :rtype: str
        """
        hosts = self.relation.get_relation_data()['mon_hosts']
        return ' '.join(sorted(hosts))

    @property
    def auth_supported(self):
        """Authentication type.

        :returns: Authentication type
        :rtype: str
        """
        return self.relation.get_relation_data()['auth']

    @property
    def key(self):
        """Key client should use when communicating with Ceph cluster.

        :returns: Key
        :rtype: str
        """
        return self.relation.get_relation_data()['key']


class GatewayClientPeerAdapter(
        ops_openstack.adapters.OpenStackOperRelationAdapter):
    """Adapter for Ceph iSCSI peer interface."""

    @property
    def gw_hosts(self):
        """List of peer addresses.

        :returns: Ceph iSCSI peer addresses.
        :rtype: str
        """
        hosts = self.relation.peer_addresses
        return ' '.join(sorted(hosts))

    @property
    def trusted_ips(self):
        """List of IP addresses permitted to use API.

        :returns: Ceph iSCSI trusted ips.
        :rtype: str
        """
        ips = copy.deepcopy(self.allowed_ips)
        ips.extend(self.relation.peer_addresses)
        return ' '.join(sorted(ips))


class TLSCertificatesAdapter(
        ops_openstack.adapters.OpenStackOperRelationAdapter):
    """Adapter for Ceph TLS Certificates interface."""

    @property
    def enable_tls(self):
        """Whether to enable TLS.

        :returns: Whether TLS should be enabled
        :rtype: bool
        """
        try:
            return bool(self.relation.application_certificate)
        except ca_client.CAClientError:
            return False


class CephISCSIGatewayAdapters(
        ops_openstack.adapters.OpenStackRelationAdapters):
    """Collection of relation adapters."""

    relation_adapters = {
        'ceph-client': CephClientAdapter,
        'cluster': GatewayClientPeerAdapter,
        'certificates': TLSCertificatesAdapter,
    }


class CephISCSIGatewayCharmBase(ops_openstack.core.OSBaseCharm):
    """Ceph iSCSI Base Charm."""

    _stored = StoredState()
    PACKAGES = ['ceph-iscsi', 'tcmu-runner', 'ceph-common']
    CEPH_CAPABILITIES = [
        "osd", "allow *",
        "mon", "allow *",
        "mgr", "allow r"]

    DEFAULT_TARGET = "iqn.2003-01.com.ubuntu.iscsi-gw:iscsi-igw"
    REQUIRED_RELATIONS = ['ceph-client', 'cluster']

    # Two has been tested but four is probably fine too but needs
    # validating
    ALLOWED_UNIT_COUNTS = [2]

    CEPH_CONFIG_PATH = Path('/etc/ceph')
    CEPH_ISCSI_CONFIG_PATH = CEPH_CONFIG_PATH / 'iscsi'
    GW_CONF = CEPH_CONFIG_PATH / 'iscsi-gateway.cfg'
    CEPH_CONF = CEPH_ISCSI_CONFIG_PATH / 'ceph.conf'
    GW_KEYRING = CEPH_ISCSI_CONFIG_PATH / 'ceph.client.ceph-iscsi.keyring'
    TLS_KEY_PATH = CEPH_CONFIG_PATH / 'iscsi-gateway.key'
    TLS_PUB_KEY_PATH = CEPH_CONFIG_PATH / 'iscsi-gateway-pub.key'
    TLS_CERT_PATH = CEPH_CONFIG_PATH / 'iscsi-gateway.crt'
    TLS_KEY_AND_CERT_PATH = CEPH_CONFIG_PATH / 'iscsi-gateway.pem'
    TLS_CA_CERT_PATH = Path(
        '/usr/local/share/ca-certificates/vault_ca_cert.crt')

    GW_SERVICES = ['rbd-target-api', 'rbd-target-gw']

    RESTART_MAP = {
        str(GW_CONF): GW_SERVICES,
        str(CEPH_CONF): GW_SERVICES,
        str(GW_KEYRING): GW_SERVICES}

    release = 'default'

    def __init__(self, framework):
        """Setup adapters and observers."""
        super().__init__(framework)
        logging.info("Using %s class", self.release)
        self._stored.set_default(
            target_created=False,
            enable_tls=False)
        self.ceph_client = ceph_client.CephClientRequires(
            self,
            'ceph-client')
        self.peers = interface_ceph_iscsi_peer.CephISCSIGatewayPeers(
            self,
            'cluster')
        self.ca_client = ca_client.CAClient(
            self,
            'certificates')
        self.adapters = CephISCSIGatewayAdapters(
            (self.ceph_client, self.peers, self.ca_client),
            self)
        self.framework.observe(
            self.ceph_client.on.broker_available,
            self.request_ceph_pool)
        self.framework.observe(
            self.ceph_client.on.pools_available,
            self.render_config)
        self.framework.observe(
            self.peers.on.has_peers,
            self.on_has_peers)
        self.framework.observe(
            self.peers.on.allowed_ips_changed,
            self.render_config)
        self.framework.observe(
            self.ca_client.on.tls_app_config_ready,
            self.on_tls_app_config_ready)
        self.framework.observe(
            self.ca_client.on.ca_available,
            self.on_ca_available)
        self.framework.observe(
            self.on.config_changed,
            self.render_config)
        self.framework.observe(
            self.on.upgrade_charm,
            self.render_config)
        self.framework.observe(
            self.on.create_target_action,
            self.on_create_target_action)
        self.framework.observe(
            self.on.add_trusted_ip_action,
            self.on_add_trusted_ip_action)

    def on_install(self, event):
        """Install packages and check substrate is supported."""
        if ch_host.is_container():
            logging.info("Installing into a container is not supported")
            self.update_status()
        else:
            self.install_pkgs()

    def on_has_peers(self, event):
        """Setup and share admin password."""
        logging.info("Unit has peers")
        if self.unit.is_leader() and not self.peers.admin_password:
            logging.info("Setting admin password")
            alphabet = string.ascii_letters + string.digits
            password = ''.join(secrets.choice(alphabet) for i in range(8))
            self.peers.set_admin_password(password)

    def request_ceph_pool(self, event):
        """Request pools from Ceph cluster."""
        logging.info("Requesting replicated pool")
        self.ceph_client.create_replicated_pool(
            self.model.config['rbd-metadata-pool'])
        logging.info("Requesting permissions")
        self.ceph_client.request_ceph_permissions(
            'ceph-iscsi',
            self.CEPH_CAPABILITIES)
        self.ceph_client.request_osd_settings({
            'osd heartbeat grace': 20,
            'osd heartbeat interval': 5})

    def refresh_request(self, event):
        """Re-request Ceph pools and render config."""
        self.render_config(event)
        self.request_ceph_pool(event)

    def render_config(self, event):
        """Render config and restart services if config files change."""
        if not self.peers.admin_password:
            logging.info("Defering setup")
            event.defer()
            return
        if not self.ceph_client.pools_available:
            logging.info("Defering setup")
            event.defer()
            return

        self.CEPH_ISCSI_CONFIG_PATH.mkdir(
            exist_ok=True,
            mode=0o750)

        def daemon_reload_and_restart(service_name):
            subprocess.check_call(['systemctl', 'daemon-reload'])
            subprocess.check_call(['systemctl', 'restart', service_name])

        rfuncs = {
            'rbd-target-api': daemon_reload_and_restart}

        @ch_host.restart_on_change(self.RESTART_MAP, restart_functions=rfuncs)
        def _render_configs():
            for config_file in self.RESTART_MAP.keys():
                ch_templating.render(
                    os.path.basename(config_file),
                    config_file,
                    self.adapters)
        logging.info("Rendering config")
        _render_configs()
        logging.info("Setting started state")
        self.peers.announce_ready()
        self._stored.is_started = True
        self.update_status()
        logging.info("on_pools_available: status updated")

    def on_ca_available(self, event):
        """Request TLS certificates."""
        addresses = set()
        for binding_name in ['public', 'cluster']:
            binding = self.model.get_binding(binding_name)
            addresses.add(binding.network.ingress_address)
            addresses.add(binding.network.bind_address)
        sans = [str(s) for s in addresses]
        sans.append(socket.gethostname())
        self.ca_client.request_application_certificate(socket.getfqdn(), sans)

    def on_tls_app_config_ready(self, event):
        """Configure TLS."""
        self.TLS_KEY_PATH.write_bytes(
            self.ca_client.application_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
        self.TLS_CERT_PATH.write_bytes(
            self.ca_client.application_certificate.public_bytes(
                encoding=serialization.Encoding.PEM))
        self.TLS_CA_CERT_PATH.write_bytes(
            self.ca_client.ca_certificate.public_bytes(
                encoding=serialization.Encoding.PEM))
        self.TLS_KEY_AND_CERT_PATH.write_bytes(
            self.ca_client.application_certificate.public_bytes(
                encoding=serialization.Encoding.PEM) +
            b'\n' +
            self.ca_client.application_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())
        )
        self.TLS_PUB_KEY_PATH.write_bytes(
            self.ca_client.application_key.public_key().public_bytes(
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                encoding=serialization.Encoding.PEM))
        subprocess.check_call(['update-ca-certificates'])
        self._stored.enable_tls = True
        self.render_config(event)

    def custom_status_check(self):
        """Custom update status checks."""
        if ch_host.is_container():
            self.unit.status = ops.model.BlockedStatus(
                'Charm cannot be deployed into a container')
            return False
        if self.peers.unit_count not in self.ALLOWED_UNIT_COUNTS:
            self.unit.status = ops.model.BlockedStatus(
                '{} is an invalid unit count'.format(self.peers.unit_count))
            return False
        return True

    # Actions

    def on_add_trusted_ip_action(self, event):
        """Add an IP to the allowed list for API access."""
        if self.unit.is_leader():
            ips = event.params.get('ips').split()
            self.peers.set_allowed_ips(
                ips,
                append=not event.params['overwrite'])
            self.render_config(event)
        else:
            event.fail("Action must be run on leader")

    def on_create_target_action(self, event):
        """Create an iSCSI target."""
        gw_client = gwcli_client.GatewayClient()
        target = event.params.get('iqn', self.DEFAULT_TARGET)
        gateway_units = event.params.get(
            'gateway-units',
            [u for u in self.peers.ready_peer_details.keys()])
        if event.params['ec-rbd-metadata-pool']:
            # When using erasure-coded pools the image needs to be pre-created
            # as the gwcli does not currently handle the creation.
            cmd = [
                'rbd',
                '--user', 'ceph-iscsi',
                '--conf', str(self.CEPH_CONF),
                'create',
                '--size', event.params['image-size'],
                '{}/{}'.format(
                    event.params['ec-rbd-metadata-pool'],
                    event.params['image-name']),
                '--data-pool', event.params['rbd-pool-name']]
            logging.info(cmd)
            subprocess.check_call(cmd)
            target_pool = event.params['ec-rbd-metadata-pool']
        else:
            target_pool = event.params['rbd-pool-name']
        gw_client.create_target(target)
        for gw_unit, gw_config in self.peers.ready_peer_details.items():
            added_gateways = []
            if gw_unit in gateway_units:
                gw_client.add_gateway_to_target(
                    target,
                    gw_config['ip'],
                    gw_config['fqdn'])
                added_gateways.append(gw_unit)
        gw_client.create_pool(
            target_pool,
            event.params['image-name'],
            event.params['image-size'])
        gw_client.add_client_to_target(
            target,
            event.params['client-initiatorname'])
        gw_client.add_client_auth(
            target,
            event.params['client-initiatorname'],
            event.params['client-username'],
            event.params['client-password'])
        gw_client.add_disk_to_client(
            target,
            event.params['client-initiatorname'],
            target_pool,
            event.params['image-name'])
        event.set_results({'iqn': target})


@ops_openstack.core.charm_class
class CephISCSIGatewayCharmOcto(CephISCSIGatewayCharmBase):
    """Ceph iSCSI Charm for Octopus."""

    _stored = StoredState()
    release = 'octopus'


if __name__ == '__main__':
    main(ops_openstack.core.get_charm_class_for_release())
