#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import docker
import json
import logging
import mock
import queue
import requests
import unittest
import socket
import tests.utils.fake as fake
import agent.common.NuvlaBoxCommon as NuvlaBoxCommon
import paho.mqtt.client as mqtt
from agent.Telemetry import Telemetry, ContainerMonitoring
from agent.monitor.IPAddressMonitor import IPAddressTelemetry


class TelemetryTestCase(unittest.TestCase):

    agent_telemetry_open = 'agent.Telemetry.open'

    def setUp(self):
        fake_nuvlabox_common = fake.Fake.imitate(NuvlaBoxCommon.NuvlaBoxCommon)
        setattr(fake_nuvlabox_common, 'container_runtime', mock.MagicMock())
        setattr(fake_nuvlabox_common, 'container_stats_json_file', 'fake-stats-file')
        setattr(fake_nuvlabox_common, 'vpn_ip_file', 'fake-vpn-file')
        Telemetry.__bases__ = (fake_nuvlabox_common,)

        self.shared_volume = "mock/path"
        self.nuvlabox_status_id = "nuvlabox-status/fake-id"
        with mock.patch('agent.Telemetry.ContainerMonitoring') as mock_container_mon:
            mock_container_mon.return_value = mock.MagicMock()
            mock_container_mon.return_value.setDaemon.return_value = None
            mock_container_mon.return_value.start.return_value = None
            self.obj = Telemetry(self.shared_volume, self.nuvlabox_status_id)
        # monkeypatching
        self.obj.mqtt_broker_host = 'fake-data-gateway'
        self.obj.mqtt_broker_port = 1
        self.obj.mqtt_broker_keep_alive = True
        self.obj.swarm_node_cert = 'swarm-cert'
        self.obj.nuvla_timestamp_format = "%Y-%m-%dT%H:%M:%SZ"
        self.obj.installation_home = '/home/fake-user'
        self.obj.nuvlabox_id = 'nuvlabox/fake-id'
        self.obj.nuvlabox_engine_version = '2.1.0'
        self.obj.hostfs = '/rootfs'
        self.obj.vulnerabilities_file = 'vuln'
        self.obj.ip_geolocation_file = 'geolocation'
        self.obj.previous_net_stats_file = 'prev-net'
        self.obj.nuvlabox_status_file = '.status'
        self.obj.vpn_ip_file = '.ip'
        self.obj.nvidia_software_power_consumption_model = {
            "ina3221x": {
                "channels": 3,
                "boards": {
                    "agx_xavier": {
                        "i2c_addresses": ["1-0040", "1-0041"],
                        "channels_path": ["1-0040/iio:device0", "1-0041/iio:device1"]
                    },
                    "nano": {
                        "i2c_addresses": ["6-0040"],
                        "channels_path": ["6-0040/iio:device0"]
                    },
                    "tx1": {
                        "i2c_addresses": ["1-0040"],
                        "channels_path": ["1-0040/iio:device0"]
                    },
                    "tx1_dev_kit": {
                        "i2c_addresses": ["1-0042", "1-0043"],
                        "channels_path": ["1-0042/iio:device2", "1-0043/iio:device3"]
                    },
                    "tx2": {
                        "i2c_addresses": ["0-0040", "0-0041"],
                        "channels_path": ["0-0040/iio:device0", "0-0041/iio:device1"]
                    },
                    "tx2_dev_kit": {
                        "i2c_addresses": ["0-0042", "0-0043"],
                        "channels_path": ["0-0042/iio:device2", "0-0043/iio:device3"]
                    }
                }
            }
        }
        ###
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_init(self):
        # make sure attrs are set and NuvlaBoxCommon is inherited
        self.assertIsNotNone(self.obj.status_default,
                             'Telemetry status not initialized')
        self.assertIsNotNone(self.obj.container_runtime,
                             'NuvlaBoxCommon not inherited')
        self.assertEqual(self.obj.status_default, self.obj.status,
                         'Failed to initialized status structures')
        self.assertIsInstance(self.obj.mqtt_telemetry, mqtt.Client)
        # gpio should be false
        self.assertFalse(self.obj.gpio_utility,
                         'Set GPIO utility to True even though there is no GPIO')

    @mock.patch('os.system')
    def test_send_mqtt(self, mock_system):
        self.obj.mqtt_telemetry = mock.MagicMock()
        self.obj.mqtt_telemetry.disconnect.return_value = None

        # if socket.timeout, just return none
        self.obj.mqtt_telemetry.connect.side_effect = socket.timeout
        self.assertIsNone(self.obj.send_mqtt(''),
                          'Failed to react to socket timeout while sending data to MQTT broker')
        self.obj.mqtt_telemetry.disconnect.assert_not_called()
        mock_system.assert_not_called()

        # if ConnectionRefusedError or socket.gaierror, disconnect and return None
        self.obj.mqtt_telemetry.connect.side_effect = ConnectionRefusedError
        self.assertIsNone(self.obj.send_mqtt(''),
                          'Failed to react to ConnectionRefusedError while sending data to MQTT broker')
        self.obj.mqtt_telemetry.disconnect.assert_called_once()
        mock_system.assert_not_called()

        self.obj.mqtt_telemetry.connect.side_effect = socket.gaierror
        self.assertIsNone(self.obj.send_mqtt(''),
                          'Failed to react to socket.gaierror while sending data to MQTT broker')
        self.assertEqual(self.obj.mqtt_telemetry.disconnect.call_count, 2,
                         'MQTT disconnect should have been called twice by now')
        mock_system.assert_not_called()

        # otherwise, send ONLY NB status to broker
        mock_system.return_value = None
        self.obj.mqtt_telemetry.connect.reset_mock(side_effect=True)
        self.obj.mqtt_telemetry.connect.return_value = None
        self.assertIsNone(self.obj.send_mqtt(''),
                          'Failed to send NuvlaBox status to MQTT broker')
        mock_system.assert_called_once()

        # and if all metrics are passed, send them ALL
        mock_system.reset_mock() # reset counter
        self.assertIsNone(self.obj.send_mqtt('', cpu='cpu', ram='ram', disks=['disk1'], energy='e1'),
                          'Failed to send multiple metrics to MQTT broker')
        self.assertEqual(mock_system.call_count, 5,
                         'Should have sent data to MQTT broker 5 times (1 per given metric)')

    def test_get_installation_parameters(self):
        self.obj.container_runtime.get_installation_parameters.return_value = 'out'
        # simple relay
        self.assertEqual(self.obj.get_installation_parameters(), 'out',
                         'Unable to get installation parameters')
        self.obj.container_runtime.get_installation_parameters.assert_called_once_with('nuvlabox.component=True')

    @mock.patch('agent.Telemetry.run')
    @mock.patch('os.path.exists')
    def test_get_swarm_node_cert_expiration_date(self, mock_exists, mock_run):
        # if swarm cert does not exist, get None
        mock_exists.return_value = False
        self.assertIsNone(self.obj.get_swarm_node_cert_expiration_date(),
                          'Tried to get swarm cert exp date even though there is no certificate')
        mock_run.assert_not_called()

        # otherwise, run openssl
        mock_exists.return_value = True
        mock_run.return_value = mock.MagicMock()

        # if openssl fails, get None
        mock_run.return_value.returncode = 1
        self.assertIsNone(self.obj.get_swarm_node_cert_expiration_date(),
                          'Tried to get swarm cert exp date even though openssl failed to execute')

        mock_run.assert_called_once()

        # otherwise, get the expiration date
        mock_run.return_value.returncode = 0
        exp_date = 'Feb  6 05:41:00 2022 GMT'
        mock_run.return_value.stdout = f'notAfter={exp_date}\n'

        self.assertEqual(self.obj.get_swarm_node_cert_expiration_date(), '2022-02-06T05:41:00Z',
                         'Unable to get Swarm node certificate expiration date')

    @mock.patch('agent.Telemetry.ContainerMonitoring')
    @mock.patch.object(Telemetry, 'get_power_consumption')
    @mock.patch.object(Telemetry, 'get_network_info')
    @mock.patch.object(Telemetry, 'get_disks_usage')
    def test_set_status_resources(self, mock_get_disk, mock_get_net, mock_get_power, mock_container_mon):
        disks = [
            {'foo-disk': 'bar'}
        ]
        mock_get_disk.return_value = disks

        self.obj.container_stats_queue = mock.MagicMock()
        self.obj.container_stats_queue.get.return_value = {'container-stats': 'fake-ones'}

        mock_get_net.return_value = [{"interface": "iface1", "bytes-transmitted": 1, "bytes-received": 2}]
        mock_get_power.return_value = [["metric", "consumption", "unit"]]

        # if all goes well, we expect a dict to be modified during the execution
        resources = {}
        self.obj.set_status_resources(resources)
        self.assertEqual(sorted(['disks', 'container-stats', 'net-stats', 'power-consumption', 'cpu', 'ram']),
                         sorted(list(resources['resources'].keys())),
                         'Failed to set status resources')

        # if QUEUE is empty, then container stats are missing
        self.obj.container_stats_queue.get.side_effect = queue.Empty
        # if ContainerMonitoring is running, do nothing
        self.obj.container_stats_monitor.is_alive.return_value = True
        mock_container_mon.return_value = mock.MagicMock()
        resources = {}
        self.obj.set_status_resources(resources)
        self.obj.container_stats_monitor.is_alive.assert_called_once()
        mock_container_mon.assert_not_called()
        self.assertEqual(sorted(['disks', 'net-stats', 'power-consumption', 'cpu', 'ram']),
                         sorted(list(resources['resources'].keys())),
                         'Failed to set status resources when container monitoring is None')

        # otherwise, restart monitoring thread
        mock_container_mon.setDaemon.return_value = None
        mock_container_mon.start.return_value = None
        self.obj.container_stats_monitor.is_alive.return_value = False
        resources = {}
        self.obj.set_status_resources(resources)
        mock_container_mon.assert_called_once()
        self.obj.container_stats_monitor.setDaemon.assert_called_once_with(True)
        self.obj.container_stats_monitor.start.assert_called_once()
        self.assertEqual(sorted(['disks', 'net-stats', 'power-consumption', 'cpu', 'ram']),
                         sorted(list(resources['resources'].keys())),
                         'Failed to set status resources when container monitoring is not running')

        self.obj.container_stats_queue.get.reset_mock(side_effect=True)
        # if POWER fails to be retrieved, do not include it
        mock_get_power.side_effect = RuntimeError
        resources = {}
        self.obj.set_status_resources(resources)
        self.assertEqual(sorted(['disks', 'container-stats', 'net-stats', 'cpu', 'ram']),
                         sorted(list(resources['resources'].keys())),
                         'Failed to set status resources when power consumption cannot be fetched')

    @mock.patch.object(Telemetry, 'get_operational_status')
    @mock.patch.object(Telemetry, 'get_operational_status_notes')
    def test_set_status_operational_status(self, mock_get_status_notes, mock_get_op_status):
        mock_get_status_notes.return_value = ['status-notes']
        mock_get_op_status.return_value = 'OPERATIONAL'
        self.obj.container_runtime.read_system_issues.return_value = ([], ['warn1', 'warn2'])
        # if all is well, and with no warning, we expect the following
        expected_out = {
            "status": 'OPERATIONAL',
            "status-notes": ['status-notes', 'warn1', 'warn2'],
        }
        body = {}
        self.obj.set_status_operational_status(body, {})
        self.assertEqual(body, expected_out,
                         'Failed to set status and operational status')

        # if installation home is not set, then a specific warning is added
        self.obj.installation_home = None
        self.obj.set_status_operational_status(body, {})
        self.assertIn("HOST_HOME not defined - SSH key management will not be functional",
                      body['status-notes'],
                      'Failed to add custom note to status when installation HOME is not set')

        # finally, if there are error, the status is automatically moved to DEGRADED
        self.obj.container_runtime.read_system_issues.return_value = (['errors'], [])
        self.obj.set_status_operational_status(body, {})
        self.assertEqual(body['status'], 'DEGRADED',
                         'Failed to set operational status to DEGRADED when there are reported errors')

    @mock.patch.object(Telemetry, 'get_vpn_ip')
    @mock.patch.object(IPAddressTelemetry, 'get_data')
    def test_set_status_ip(self, mock_vpn_ip):
        self.obj.container_runtime.get_api_ip_port.return_value = ('1.1.1.1', 0)
        # if VPN IP is set, use it
        mock_vpn_ip.return_value = '2.2.2.2'
        body = {}
        self.obj.set_status_ip(body)
        self.assertEqual(body['ip'], '2.2.2.2',
                         'Failed to set VPN IP')

        self.obj.container_runtime.get_api_ip_port.assert_not_called()
        # otherwise, infer it from container runtime
        mock_vpn_ip.return_value = None
        self.obj.set_status_ip(body)
        self.assertEqual(body['ip'], '1.1.1.1',
                         'Failed to set VPN IP as inferred by container runtime')

        self.obj.container_runtime.get_api_ip_port.assert_called_once()

    @mock.patch.object(Telemetry, 'get_docker_server_version')
    def test_set_status_coe_version(self, mock_docker_version):
        self.obj.container_runtime.get_kubelet_version.return_value = 'k1'
        mock_docker_version.return_value = 'd1'

        # if versions are found, they are added to body
        body = {}
        self.obj.set_status_coe_version(body)
        self.assertEqual(body, {'docker-server-version': 'd1', 'kubelet-version': 'k1'},
                         'Failed to set Docker and Kubelet versions')

        # if docker version is not found, then it is not added either
        mock_docker_version.return_value = None
        body = {}
        self.obj.set_status_coe_version(body)
        self.assertNotIn('docker-server-version', body,
                         'Added Docker version to status body even though we could not find a version')

        # same for kubelet version, including when exceptions occur
        self.obj.container_runtime.get_kubelet_version.return_value = None
        body = {}
        self.obj.set_status_coe_version(body)
        self.assertNotIn('kubelet-version', body,
                         'Added Kubelet version to status body even though we could not find a version')

        self.obj.container_runtime.get_kubelet_version.side_effect = NameError
        body = {}
        self.obj.set_status_coe_version(body)
        self.assertEqual(body, {},
                         'Added Kubelet version to status body even though there was an error getting it')

    def test_get_cluster_manager_attrs(self):
        # if node_id not in managers , get False and []
        self.assertEqual(self.obj.get_cluster_manager_attrs([], 'node-id'), (False, []),
                         'Tried to get Cluster manager attrs even though node is not a manager')

        # otherwise, get nodes
        node_1 = fake.MockDockerNode()
        node_2 = fake.MockDockerNode()
        self.obj.container_runtime.list_nodes.return_value = [node_1, node_2]
        # if there's an error, get False and [] again
        self.obj.container_runtime.list_nodes.side_effect = docker.errors.APIError('', requests.Response())
        self.assertEqual(self.obj.get_cluster_manager_attrs(['node-id'], 'node-id'), (False, []),
                         'Returned cluster attrs even though nodes could not be listed')

        # otherwise, return nodes if active
        self.obj.container_runtime.is_node_active.return_value = True
        self.obj.container_runtime.list_nodes.reset_mock(side_effect=True)
        self.assertEqual(self.obj.get_cluster_manager_attrs(['node-id'], 'node-id'), (True, [node_1.id, node_2.id]),
                         'Failed to get cluster manager attributes')

        self.obj.container_runtime.is_node_active.return_value = False
        self.assertEqual(self.obj.get_cluster_manager_attrs(['node-id'], 'node-id'), (True, []),
                         'Failed to get cluster manager attributes when no nodes are active')

    @mock.patch.object(Telemetry, 'get_cluster_manager_attrs')
    def test_set_status_cluster(self, mock_get_cluster_manager_attrs):
        mock_get_cluster_manager_attrs.return_value = (False, [])
        self.obj.container_runtime.get_cluster_join_address.return_value = None
        # if there's no node-id, then certain keys shall not be in body
        self.obj.container_runtime.get_node_id.return_value = None
        body = {}
        self.obj.set_status_cluster(body, {})
        self.assertTrue(all(x not in body for x in ["node-id", "orchestrator", "cluster-node-role"]),
                        'Node ID attrs were included in status body even though there is no Node ID')

        # if cluster-id is None, then it is not added
        self.obj.container_runtime.get_cluster_id.return_value = None
        body = {}
        self.obj.set_status_cluster(body, {})
        self.assertNotIn('cluster-id', body,
                         'Cluster ID was added to status even though it does not exist')

        # same for cluster-managers
        self.obj.container_runtime.get_cluster_managers.return_value = []
        body = {}
        self.obj.set_status_cluster(body, {})
        self.assertNotIn('cluster-managers', body,
                         'Cluster managers were added to status even though there are none')

        self.obj.container_runtime.get_node_id.return_value = 'node-id'
        # if node is not a manager, skip those fields
        self.obj.container_runtime.get_cluster_managers.return_value = ['node-id-2']
        body = {}
        self.obj.set_status_cluster(body, {})
        self.obj.container_runtime.get_cluster_join_address.assert_called_once()
        self.assertEqual(body['node-id'], 'node-id',
                         'Node ID does not match')
        self.assertEqual(body['cluster-node-role'], 'worker',
                         'Saying node is not a worker when it is')

        # if it is a manager, then get all manager related attrs
        self.obj.container_runtime.get_cluster_id.return_value = 'cluster-id'
        self.obj.container_runtime.get_cluster_managers.return_value = ['node-id']
        mock_get_cluster_manager_attrs.return_value = (True, ['node-id'])
        self.obj.container_runtime.get_cluster_join_address.return_value = 'addr:port'
        body = {}
        self.obj.set_status_cluster(body, {})
        all_fields = ["node-id", "orchestrator", "cluster-node-role", "cluster-id",
                      "cluster-join-address", "cluster-managers", "cluster-nodes"]
        self.assertEqual(sorted(all_fields), sorted(list(body.keys())),
                         'Unable to set cluster status')

    @mock.patch.object(Telemetry, 'get_installation_parameters')
    def test_set_status_installation_params(self, mock_get_install_params):
        # if no install params, don't include them
        body = {}
        mock_get_install_params.return_value = None
        self.obj.set_status_installation_params(body)
        self.assertNotIn('installation-parameters', body,
                         'Set installation-parameters when there are none')

        mock_get_install_params.return_value = 'fake-params'
        self.obj.set_status_installation_params(body)
        self.assertEqual(body['installation-parameters'], 'fake-params',
                         'Unable to set installation parameters in NB status body')

    @mock.patch.object(Telemetry, 'get_swarm_node_cert_expiration_date')
    def test_set_status_coe_cert_expiration_date(self, mock_get_swarm_node_cert_expiration_date):
        # for k8s is None
        NuvlaBoxCommon.ORCHESTRATOR = 'kubernetes'
        self.assertIsNone(self.obj.set_status_coe_cert_expiration_date({}),
                          'Tried to set COE cert expiration for Kubernetes COE')

        NuvlaBoxCommon.ORCHESTRATOR = 'docker'
        mock_get_swarm_node_cert_expiration_date.return_value = None
        body = {}
        self.obj.set_status_coe_cert_expiration_date(body)
        self.assertNotIn('swarm-node-cert-expiry-date', body,
                         'swarm-node-cert-expiry-date was added to status even though it does not exist')

        mock_get_swarm_node_cert_expiration_date.side_effect = RuntimeError
        # same for errors
        self.obj.set_status_coe_cert_expiration_date(body)
        self.assertNotIn('swarm-node-cert-expiry-date', body,
                         'swarm-node-cert-expiry-date was added to status even though there was an error getting it')

        # otherwise
        mock_get_swarm_node_cert_expiration_date.reset_mock(side_effect=True)
        mock_get_swarm_node_cert_expiration_date.return_value = 'date'
        self.obj.set_status_coe_cert_expiration_date(body)
        self.assertEqual(body['swarm-node-cert-expiry-date'], 'date',
                         'Unable to set swarm-node-cert-expiry-date in statusz')

    @mock.patch.object(Telemetry, 'get_temperature')
    def test_set_status_temperatures(self, mock_get_temperature):
        # simple lookup and conditional setting
        mock_get_temperature.return_value = None
        body = {}
        self.obj.set_status_temperatures(body)
        self.assertNotIn('temperatures', body,
                         'Temperatures were set even though they are None')

        mock_get_temperature.return_value = 'temp'
        self.obj.set_status_temperatures(body)
        self.assertEqual(body['temperatures'], 'temp',
                         'Failed to set temperatures in status')

    @mock.patch.object(Telemetry, 'get_gpio_pins')
    def test_set_status_gpio(self, mock_get_gpio_pins):
        # conditional setting again
        self.obj.gpio_utility = False
        body = {}
        self.obj.set_status_gpio(body)
        self.assertNotIn('gpio-pins', body,
                         'Set GPIO but should not have')
        mock_get_gpio_pins.assert_not_called()

        self.obj.gpio_utility = True
        mock_get_gpio_pins.return_value = None
        self.obj.set_status_gpio(body)
        self.assertNotIn('gpio-pins', body,
                         'Set GPIO even though they do not exist')
        mock_get_gpio_pins.assert_called_once()
        mock_get_gpio_pins.return_value = 'gpio'
        self.obj.set_status_gpio(body)
        self.assertEqual(body['gpio-pins'], 'gpio',
                         'Failed to set GPIO pins in status')

    @mock.patch.object(Telemetry, 'get_ip_geolocation')
    def test_set_status_inferred_location(self, mock_get_ip_geolocation):
        # conditional setting
        mock_get_ip_geolocation.return_value = None
        body = {}
        self.obj.set_status_inferred_location(body)
        self.assertNotIn('inferred-location', body,
                         'Set inferred-location when there is not one')

        mock_get_ip_geolocation.return_value = 'location'
        self.obj.set_status_inferred_location(body)
        self.assertEqual(body['inferred-location'], 'location',
                         'Failed to set inferred-location')

    @mock.patch.object(Telemetry, 'get_security_vulnerabilities')
    def test_set_status_vulnerabilities(self, mock_get_security_vulnerabilities):
        # if there are none, do nothing
        body = {}
        mock_get_security_vulnerabilities.return_value = None
        self.obj.set_status_vulnerabilities(body)
        self.assertNotIn('vulnerabilities', body,
                         'Set vulnerabilities in status when there are none')

        mock_get_security_vulnerabilities.return_value = [
            {
                "product": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.5",
                "vulnerability-id": "CVE-2021-28041",
                "vulnerability-score": 7.1
            }
        ]
        self.obj.set_status_vulnerabilities(body)
        self.assertEqual(['items', 'summary'], sorted(body['vulnerabilities'].keys()),
                         'Unable to set vulnerabilities in status')
        expected_out = {
            'items': [{
                "product": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.5",
                "vulnerability-id": "CVE-2021-28041",
                "vulnerability-score": 7.1
            }],
            'summary': {
                'total': 1,
                'affected-products': ["OpenSSH 7.6p1 Ubuntu 4ubuntu0.5"],
                'average-score': 7.1
            }
        }
        logging.error(body)
        self.assertEqual(body['vulnerabilities'], expected_out,
                         'Status vulnerabilities do not match the real ones')

    @mock.patch.object(Telemetry, 'send_mqtt')
    @mock.patch.object(Telemetry, 'set_status_inferred_location')
    @mock.patch.object(Telemetry, 'set_status_vulnerabilities')
    @mock.patch.object(Telemetry, 'set_status_gpio')
    @mock.patch.object(Telemetry, 'set_status_temperatures')
    @mock.patch.object(Telemetry, 'set_status_coe_cert_expiration_date')
    @mock.patch.object(Telemetry, 'set_status_installation_params')
    @mock.patch.object(Telemetry, 'set_status_cluster')
    @mock.patch.object(Telemetry, 'set_status_coe_version')
    @mock.patch.object(Telemetry, 'set_status_ip')
    @mock.patch.object(Telemetry, 'set_status_operational_status')
    @mock.patch.object(Telemetry, 'set_status_resources')
    def test_get_status(self, mock_set_status_resources,
                        mock_set_status_operational_status, mock_set_status_ip,
                        mock_set_status_coe_version, mock_set_status_cluster,
                        mock_set_status_installation_params, mock_set_status_coe_cert_expiration_date,
                        mock_set_status_temperatures, mock_set_status_gpio,
                        mock_set_status_vulnerabilities, mock_set_status_inferred_location, mock_send_mqtt):
        self.obj.container_runtime.get_node_info.return_value = fake.MockDockerNode()
        self.obj.container_runtime.get_host_os.return_value = 'os'
        self.obj.container_runtime.get_host_architecture.return_value = 'arch'
        self.obj.container_runtime.get_hostname.return_value = 'hostname'
        self.obj.container_runtime.get_container_plugins.return_value = ['plugin']

        # these functions are already tested elsewhere
        mock_set_status_resources.return_value = mock_set_status_operational_status.return_value = \
            mock_set_status_ip.return_value = mock_set_status_coe_version.return_value = \
            mock_set_status_cluster.return_value = mock_set_status_installation_params.return_value = \
            mock_set_status_coe_cert_expiration_date.return_value = mock_set_status_temperatures.return_value = \
            mock_set_status_gpio.return_value = mock_set_status_vulnerabilities.return_value = \
            mock_send_mqtt.return_value = mock_set_status_inferred_location.return_value = None

        mock_set_status_resources.side_effect = self.obj.status_default.update({
            'resources': {},
        })
        # forget about the above mocks, and focus on the attrs that are actually set during this method

        status_for_nuvla, all_status = self.obj.get_status()

        # all "Gets" were called
        mock_send_mqtt.assert_called_once_with(status_for_nuvla, None, None, [])

        # the following fields are set within this method:
        new_fields = ['operating-system', 'architecture', 'hostname', 'last-boot', 'container-plugins',
                      'host-user-home', 'nuvlabox-engine-version']
        self.assertTrue(all(status_for_nuvla[k] is not None for k in new_fields),
                        'Failed to set status attributes during get_status')

        # all_status contains additional fields
        additional_fields = ["cpu-usage", "cpu-load", "disk-usage", "memory-usage", "cpus", "memory", "disk"]
        self.assertTrue(all(k in all_status for k in additional_fields),
                        'Failed to set additional status attributes for all_status, during get_status')

    def test_get_docker_server_version(self):
        self.obj.container_runtime.client.version.return_value = {'Version': 1}
        self.assertEqual(self.obj.get_docker_server_version(), 1,
                         'Failed to get Docker server version')

        # when there's an error, get None
        self.obj.container_runtime.client.version.side_effect = RuntimeError
        self.assertIsNone(self.obj.get_docker_server_version(),
                          'Got a Docker version even though there was an error')

    @mock.patch.object(Telemetry, 'read_temperature_files')
    @mock.patch('os.listdir')
    @mock.patch('os.path.exists')
    def test_get_temperature(self, mock_exists, mock_listdir, mock_read_temperature_files):
        # if thermal path doesn't exist, get values from psutil
        mock_exists.return_value = False
        self.assertIsInstance(self.obj.get_temperature(), list,
                              'Did not get list out of get_temperature')
        # and stops there, thus listdir is not called
        mock_listdir.assert_not_called()

        # otherwise, if thermal paths do no exist, return []
        mock_listdir.return_value = ['dir1', 'dir2']
        mock_exists.side_effect = [True, False, False]
        self.assertEqual(self.obj.get_temperature(), [],
                         'Failed to get temperature when thermal files do not exist')
        mock_listdir.assert_called_once()

        # same if thermal files do not exist
        mock_listdir.return_value = ['thermal-dir1', 'thermal-dir2']
        self.assertEqual(self.obj.get_temperature(), [],
                         'Failed to get temperature when thermal files do not exist')

        # if they exist, we can open them, but if there's an error reading them or they are None, we get [] again
        mock_read_temperature_files.return_value = (None, None)
        mock_exists.reset_mock(side_effect=True)
        mock_exists.return_value = True
        self.assertEqual(self.obj.get_temperature(), [],
                         'Failed to get temperature when thermal files have invalid content')

        # if readings succeed, but values are not of the right type, get []
        mock_read_temperature_files.return_value = ('metric', 'bad-type-value')
        self.assertEqual(self.obj.get_temperature(), [],
                         'Failed to get temperature when thermal files have content of the wrong type')

        # otherwise, get temperatures
        mock_read_temperature_files.return_value = ('metric', 1000)
        expected_output = [{
            "thermal-zone": 'metric',
            "value": 1
        }, {
            "thermal-zone": 'metric',
            "value": 1
        }]
        self.assertEqual(self.obj.get_temperature(), expected_output,
                         'Failed to get temperatures')

    def test_read_temperature_files(self):
        # if there's an error reading files, return None,None
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data=None)):
            self.assertEqual(self.obj.read_temperature_files('', ''), (None, None),
                             'Failed to read temperature files when one cannot be read')

        # if files can be read, return their content
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='test')):
            self.assertEqual(self.obj.read_temperature_files('', ''), ('test', 'test'),
                             'Failed to read temperature files')

    @mock.patch('os.listdir')
    @mock.patch('os.path.exists')
    def test_get_power_consumption(self, mock_exists, mock_listdir):
        # if i2c path doesn't exist, get []
        mock_exists.return_value = False
        self.assertEqual(self.obj.get_power_consumption(), [],
                         'Got power consumption even when I2C drivers cannot be found')

        # else, go through the model
        mock_exists.return_value = True
        # if addresses do not match, get [] again
        mock_listdir.return_value = ['not-match']
        self.assertEqual(self.obj.get_power_consumption(), [],
                         'Got power consumption even I2C addresses do not match')

        # otherwise
        mock_listdir.return_value = ['0-0040', '0-0041']
        # if metrics_folder_path does not exist, get []
        mock_exists.side_effect = [True] + \
                                  [False for _ in
                                   range(0,
                                         len(self.obj.nvidia_software_power_consumption_model['ina3221x']['boards']))]
        self.assertEqual(self.obj.get_power_consumption(), [],
                         'Got power consumption even though I2C metrics_folder_path do not exist')

        # NOTE: ['0-0040', '0-0041'] only matches with 2 boards
        # if metrics_folder_path exists, rail file must exist as well otherwise get []
        mock_exists.side_effect = [True] + \
                                  [False, True] + [False, False, False]     # 2 boards matching + 3 channels/board
        self.assertEqual(self.obj.get_power_consumption(), [],
                         'Got power consumption even though I2C rail files do not exist')

        # if rail files exist, open them, unless there is an error, which means = []
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data=None)):
            mock_exists.side_effect = [True] + \
                                      [False, True] + [True, True, True]     # 2 boards matching + 3 channels
            self.assertEqual(self.obj.get_power_consumption(), [],
                             'Got power consumption when rail files cannot be read')

        # if reading goes well, but metrics_folder_path is empty, get []
        mock_exists.side_effect = [True] + \
                                  [False, True] + [True, True, True]     # 2 boards matching + 3 channels
        mock_listdir.side_effect = [['0-0040', '0-0041'],
                                    [], [], []]   # 3 channel reading
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='valid_data')):
            self.assertEqual(self.obj.get_power_consumption(), [],
                             'Got power consumption when rail files cannot be read')

        # if reading data is valid and metrics_folder_path contains the desired metric matches
        mock_exists.side_effect = [True] + \
                                  [False, True] + [True, True, True]     # 2 boards matching + 3 channels
        channel = 0
        list_dir_right_sequence = [['0-0040', '0-0041'],
                                   [f'in_current{channel}_input',
                                    f'in_voltage{channel}_input',
                                    f'in_power{channel}_input',
                                    f'crit_current_limit_{channel}'], [], []]   # 3 channel reading (1st valid)
        mock_listdir.side_effect = list_dir_right_sequence

        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='not-float-data')):
            self.assertEqual(self.obj.get_power_consumption(), [],
                             'Got power consumption when rail files can be read but do not have data as a float')

        mock_exists.side_effect = [True] + \
                                  [False, True] + [True, True, True]     # 2 boards matching + 3 channels
        channel = 0
        mock_listdir.side_effect = list_dir_right_sequence
        expected_output = [
            {'energy-consumption': 1, 'metric-name': '1_current', 'unit': 'mA'},
            {'energy-consumption': 1, 'metric-name': '1_voltage', 'unit': 'mV'},
            {'energy-consumption': 1, 'metric-name': '1_power', 'unit': 'mW'},
            {'energy-consumption': 1, 'metric-name': '1_critical_current_limit', 'unit': 'mA'}
        ]

        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='1')):
            self.assertEqual(self.obj.get_power_consumption(), expected_output,
                             'Unable to get power consumption')

    @mock.patch('os.path.exists')
    def test_get_security_vulnerabilities(self, mock_exists):
        # just open and read file if it exists
        mock_exists.return_value = False
        self.assertIsNone(self.obj.get_security_vulnerabilities(),
                          'Vulnerabilities file does not exist but still returned something')

        mock_exists.return_value = True
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='{"foo": "bar"}')):
            self.assertEqual(self.obj.get_security_vulnerabilities(), {"foo": "bar"},
                             'Unable to get security vulnerabilities')

    def test_parse_gpio_pin_cell(self):
        # too few indexes, get None
        self.assertIsNone(self.obj.parse_gpio_pin_cell([], '1|2'),
                          'Got parsed GPIO pins when indexes are fewer than expected')

        # example of a GPIO readall
        # +-----+-----+---------+------+---+---Pi 4B--+---+------+---------+-----+-----+
        # | BCM | wPi |   Name  | Mode | V | Physical | V | Mode | Name    | wPi | BCM |
        # +-----+-----+---------+------+---+----++----+---+------+---------+-----+-----+
        # |     |     |    3.3v |      |   |  1 || 2  |   |      | 5v      |     |     |
        # |   2 |   8 |   SDA.1 |   IN | 1 |  3 || 4  |   |      | 5v      |     |     |
        # |   3 |   9 |   SCL.1 |   IN | 1 |  5 || 6  |   |      | 0v      |     |     |
        # ...

        # let's take a valid line: pins 3 and 4
        gpio_line = ' |   2 |   8 |   SDA.1 |   IN | 1 |  3 || 4  |   |      | 5v      |     |     |'
        first_pin_indexes = [1, 3, 4, 5, 6]
        second_pin_indexes = [14, 11, 10, 9, 8]

        # first, we need to read an int from the line, and if this is not possible, get None
        # index 3 cannot be converted to int:
        self.assertIsNone(self.obj.parse_gpio_pin_cell([0, 0, 0, 0, 3], gpio_line),
                          'Failed to get No GPIO info when values cannot be converted to int')

        # same for any other exception (like IndexError)
        self.assertIsNone(self.obj.parse_gpio_pin_cell([0, 0, 0, 0, 333], gpio_line),
                          'Failed to get No GPIO info reading error occurs')

        # if all goes well, the above values should be casted to their right var type, and returned in a dict
        expected_output_pin_3 = {
            'bcm': 2,
            'name': 'SDA.1',
            'mode': 'IN',
            'voltage': 1,
            'pin': 3
        }
        expected_output_pin_4 = {
            'name': '5v',
            'pin': 4
        }
        self.assertEqual(self.obj.parse_gpio_pin_cell(first_pin_indexes, gpio_line), expected_output_pin_3,
                         'Failed to parse left side GPIO pin')
        self.assertEqual(self.obj.parse_gpio_pin_cell(second_pin_indexes, gpio_line), expected_output_pin_4,
                         'Failed to parse right side GPIO pin')

    @mock.patch('agent.Telemetry.run')
    def test_get_gpio_pins(self, mock_run):
        run = mock.MagicMock()
        # if the gpio command fails, get None
        run.returncode = 1
        mock_run.return_value = run
        self.assertIsNone(self.obj.get_gpio_pins(),
                          'Tried to get GPIO pins when `gpio readall` has failed')

        # same in case the stdout is null
        run.returncode = 0
        run.stdout = ''
        mock_run.return_value = run
        self.assertIsNone(self.obj.get_gpio_pins(),
                          'Tried to get GPIO pins when `gpio readall` returned nothing')

        # if stdout does not have the right format, we get []
        run.stdout = 'wrong format'
        mock_run.return_value = run
        self.assertEqual(self.obj.get_gpio_pins(), [],
                         'Got GPIO info even though the probe failed to get the proper system information')

        # a correct stdout has the following structure
        run.stdout = '\n\n\n |   2 |   8 |   SDA.1 |   IN | 1 |  3 || 4  |   |      | 5v      |     |     |\n\n\n\n'

        # for this line, there are 2 pins, so we expect a two item list
        mock_run.return_value = run
        self.assertEqual(len(self.obj.get_gpio_pins()), 2,
                         'Failed to return the right number of GPIO pins')

        expected_output = [
            {
                'bcm': 2,
                'name': 'SDA.1',
                'mode': 'IN',
                'voltage': 1,
                'pin': 3
            }, {
                'name': '5v',
                'pin': 4
            }
        ]
        self.assertEqual(self.obj.get_gpio_pins(), expected_output,
                         'Unable to get GPIO pins')

    def test_reuse_previous_geolocation(self):
        # if a previous geolocation file doesn't exist, then return None
        with mock.patch(self.agent_telemetry_open) as mock_open:
            mock_open.side_effect = FileNotFoundError
            self.assertIsNone(self.obj.reuse_previous_geolocation(0),
                              'Tried to reuse a previous geolocation that does not exist')

        # same for any other exception
        with mock.patch(self.agent_telemetry_open) as mock_open:
            mock_open.side_effect = [json.decoder.JSONDecodeError, KeyError, Exception]
            for _ in range(0, 3):
                self.assertIsNone(self.obj.reuse_previous_geolocation(0),
                                  'Tried to reuse a previous geolocation even though there was an error reading it')

        # if it exists, read it, and compare timestamps
        self.obj.time_between_get_geolocation = 10
        # if the time elapsed is greater than interval, then get None
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='{"timestamp": 1}')):
            # 19 sec difference, > than 10
            self.assertIsNone(self.obj.reuse_previous_geolocation(20),
                              'Tried to reuse a previous geolocation when a new one should be used instead')

        # otherwise, get coordinates
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='{"timestamp": 1, "coordinates": "test"}')):
            # 1 sec difference, < than 10
            self.assertEqual(self.obj.reuse_previous_geolocation(2), "test",
                             'Failed to reuse previous geolocation coordinates')

    def test_parse_geolocation(self):
        # when using a service with "coordinates_key"
        ip_location_service_name = 'ipinfo.io'
        ip_location_service_info = self.obj.ip_geolocation_services[ip_location_service_name]
        # the request response must container that key
        # if it is a string, give it back as a list and reversed
        geolocation_response = {
            ip_location_service_info['coordinates_key']: 'one,two'
        }
        self.assertEqual(self.obj.parse_geolocation(ip_location_service_name,
                                                    ip_location_service_info,
                                                    geolocation_response), ['two', 'one'],
                         'Failed to get geolocation from string coordinates_key')

        # if it is a list, get it reversed
        geolocation_response = {
            ip_location_service_info['coordinates_key']: ['one', 'two']
        }
        self.assertEqual(self.obj.parse_geolocation(ip_location_service_name,
                                                    ip_location_service_info,
                                                    geolocation_response), ['two', 'one'],
                         'Failed to get geolocation from list coordinates_key')

        # else, raise a TypeError
        geolocation_response = {
            ip_location_service_info['coordinates_key']: {}
        }
        self.assertRaises(TypeError, self.obj.parse_geolocation,
                          ip_location_service_name, ip_location_service_info, geolocation_response)

        # and if it is not included in the HTTP response, raise KeyError
        self.assertRaises(KeyError, self.obj.parse_geolocation,
                          ip_location_service_name, ip_location_service_info, {})

        # without a "coordinates_key"
        ip_location_service_name = 'ip-api.com'
        ip_location_service_info = self.obj.ip_geolocation_services[ip_location_service_name]
        geolocation_response = {
            ip_location_service_info['longitude_key']: 1,
            ip_location_service_info['latitude_key']: 2
        }
        # gets the respective coord keys from the HTTP response
        self.assertEqual(self.obj.parse_geolocation(ip_location_service_name,
                                                    ip_location_service_info,
                                                    geolocation_response), [1, 2],
                         'Failed to get geolocation using longitude and latitude')

        # if altitude also exists, it is also included
        ip_location_service_info['altitude_key'] = 'altitude'
        geolocation_response['altitude'] = 3
        self.assertEqual(self.obj.parse_geolocation(ip_location_service_name,
                                                    ip_location_service_info,
                                                    geolocation_response), [1, 2, 3],
                         'Failed to get geolocation using longitude and latitude and altitude')
        # and if such keys are not present in the response, raise keyerror
        self.assertRaises(KeyError, self.obj.parse_geolocation,
                          ip_location_service_name, ip_location_service_info, {})

    @mock.patch('agent.Telemetry.requests.get')
    @mock.patch.object(Telemetry, 'parse_geolocation')
    @mock.patch.object(Telemetry, 'reuse_previous_geolocation')
    def test_get_ip_geolocation(self, mock_reuse_previous_geolocation, mock_parse_geolocation, mock_get):
        # if time elapsed since last run is smaller than expected frequency, return the previous coordinates
        mock_reuse_previous_geolocation.return_value = 'previous'
        self.assertEqual(self.obj.get_ip_geolocation(), 'previous',
                         'Failed to get previous geolocation when next cycle has not been reached yet')

        # otherwise
        mock_reuse_previous_geolocation.return_value = None
        # go through the geolocation services, do a GET
        # if all GETs fail, return []

        mock_get.side_effect = TimeoutError
        self.assertEqual(self.obj.get_ip_geolocation(), [],
                         'Returned geolocation even though all requests failed')
        self.assertEqual(mock_get.call_count, len(self.obj.ip_geolocation_services.keys()),
                         'When all fail, all geolocation services must be used to query geolocation')

        # if GET succeeds, try to parse it
        mock_get.reset_mock(side_effect=True)

        response = mock.MagicMock()
        response.json.return_value = {}
        mock_get.return_value = response

        # if parsing fails, for whatever reason, get []
        mock_parse_geolocation.side_effect = [KeyError] + ([Exception]*(len(self.obj.ip_geolocation_services.keys())-1))
        for _ in range(0, len(self.obj.ip_geolocation_services.keys())):
            self.assertEqual(self.obj.get_ip_geolocation(), [],
                             'Returned geolocation even though parsing could not be done')

        # otherwise, return the parsed location
        mock_parse_geolocation.reset_mock(side_effect=True)
        mock_parse_geolocation.return_value = [1, 2]

        with mock.patch(self.agent_telemetry_open) as mock_open:
            self.assertEqual(self.obj.get_ip_geolocation(), [1, 2],
                             'Unable to get geolocation')
            # file must have been written
            mock_open.assert_called_once_with(self.obj.ip_geolocation_file, 'w')

    @mock.patch('json.loads')
    @mock.patch('os.listdir')
    def test_get_network_info(self, mock_ls, mock_json_loads):
        # if sys path does not exist, get {}
        mock_ls.side_effect = FileNotFoundError
        self.assertEqual(self.obj.get_network_info(), [],
                         'Got net info even though /sys path cannot be found')

        mock_ls.reset_mock(side_effect=True)
        # if previous net file cannot be found, or is malformed, don't load it
        with mock.patch(self.agent_telemetry_open) as mock_open:
            mock_open.side_effect = [FileNotFoundError, mock.MagicMock()]
            mock_ls.return_value = []   # no interfaces, get []
            self.assertEqual(self.obj.get_network_info(), [],
                             'Got net info even though no interfaces were found')
            mock_json_loads.assert_not_called()

        # if there are interfaces
        mock_ls.return_value = ['iface1', 'iface2']
        # try to open but if it fails, get []
        with mock.patch(self.agent_telemetry_open) as mock_open:
            mock_open.side_effect = [FileNotFoundError, FileNotFoundError, NotADirectoryError, mock.MagicMock()]
            self.assertEqual(self.obj.get_network_info(), [],
                             'Got net info even though interfaces files cannot be read')

        # the first time it runs, there are no previous net stats
        self.assertEqual(self.obj.first_net_stats, {},
                         'First net stats is not empty before first run')

        expected_first_net_stats = {
            'iface1': {
                "bytes-transmitted": 2,
                "bytes-received": 1,
                "bytes-transmitted-carry": 0,
                "bytes-received-carry": 0
            },
            'iface2': {
                "bytes-transmitted": 4,
                "bytes-received": 3,
                "bytes-transmitted-carry": 0,
                "bytes-received-carry": 0
            }
        }
        with mock.patch(self.agent_telemetry_open) as mock_open:
            # 4 readers because open tx and rx per interface (2x2)
            mock_open.side_effect = [FileNotFoundError,
                                     mock.mock_open(read_data='1').return_value,
                                     mock.mock_open(read_data='2').return_value,
                                     mock.mock_open(read_data='3').return_value,
                                     mock.mock_open(read_data='4').return_value, mock.MagicMock()]
            # first time is all 0
            self.assertEqual(self.obj.get_network_info(), [
                {'interface': 'iface1', 'bytes-transmitted': 0, 'bytes-received': 0},
                {'interface': 'iface2', 'bytes-transmitted': 0, 'bytes-received': 0}
            ],
                             'Failed to get net stats')

            self.assertEqual(self.obj.first_net_stats, expected_first_net_stats,
                             'Unable to set first_net_stats after first run')

        # now that first_net_stats exists, if system counter are still going, get the diff and return values
        with mock.patch(self.agent_telemetry_open) as mock_open:
            # 4 readers because open tx and rx per interface (2x2)
            mock_open.side_effect = [FileNotFoundError,
                                     mock.mock_open(read_data='10').return_value,
                                     mock.mock_open(read_data='10').return_value,
                                     mock.mock_open(read_data='20').return_value,
                                     mock.mock_open(read_data='20').return_value, mock.MagicMock()]
            # current-first+carry=x -> 20-4+0-16
            self.assertEqual(self.obj.get_network_info(), [
                {'interface': 'iface1', 'bytes-transmitted': 8, 'bytes-received': 9},
                {'interface': 'iface2', 'bytes-transmitted': 16, 'bytes-received': 17}
            ],
                             'Failed to get net stats on a 2nd run')
            # first_net_stats is not changed anymore
            self.assertEqual(self.obj.first_net_stats, expected_first_net_stats,
                             'first_net_stats were changed when they should not have')

        # when system counters are reset, the reads are smaller than the first ones
        with mock.patch(self.agent_telemetry_open) as mock_open:
            # 4 readers because open tx and rx per interface (2x2)
            mock_open.side_effect = [FileNotFoundError,
                                     mock.mock_open(read_data='0').return_value,
                                     mock.mock_open(read_data='1').return_value,
                                     mock.mock_open(read_data='2').return_value,
                                     mock.mock_open(read_data='3').return_value, mock.MagicMock()]
            # assuming once more previous_stats don't exist, we should get the reading as is
            self.assertEqual(self.obj.get_network_info(), [
                {'interface': 'iface1', 'bytes-transmitted': 1, 'bytes-received': 0},
                {'interface': 'iface2', 'bytes-transmitted': 3, 'bytes-received': 2}
            ],
                             'Failed to get net stats after counter reset')
            # first_net_stats is NOW changed because of reset
            new_first_stats = {
                'iface1': {
                    "bytes-transmitted": 1,
                    "bytes-received": 0,
                    "bytes-transmitted-carry": 0,
                    "bytes-received-carry": 0
                },
                'iface2': {
                    "bytes-transmitted": 3,
                    "bytes-received": 2,
                    "bytes-transmitted-carry": 0,
                    "bytes-received-carry": 0
                }
            }
            self.assertEqual(self.obj.first_net_stats, new_first_stats,
                             'first_net_stats did not change after system counters reset')

        # finally, if previous stats exist, and counters are reset, get their value + current readings
        with mock.patch(self.agent_telemetry_open) as mock_open:
            previous_net_stats = {
                'iface1': {
                    "bytes-transmitted": 1,
                    "bytes-received": 1
                },
                'iface2': {
                    "bytes-transmitted": 2,
                    "bytes-received": 2
                }
            }
            mock_json_loads.return_value = previous_net_stats
            # 4 readers because open tx and rx per interface (2x2)
            mock_open.side_effect = [mock.mock_open(read_data=json.dumps(previous_net_stats)).return_value,
                                     mock.mock_open(read_data='0').return_value,
                                     mock.mock_open(read_data='0').return_value,
                                     mock.mock_open(read_data='1').return_value,
                                     mock.mock_open(read_data='1').return_value, mock.MagicMock()]
            # result is the sum of previous + current
            self.assertEqual(self.obj.get_network_info(), [
                {'interface': 'iface1', 'bytes-transmitted': 1, 'bytes-received': 1},
                {'interface': 'iface2', 'bytes-transmitted': 3, 'bytes-received': 3}
            ],
                             'Failed to get net stats after counter reset, having previous net stats')
            # first_net_stats is NOW changed because of reset, considering previous stats
            new_first_stats = {
                'iface1': {
                    "bytes-transmitted": 0,
                    "bytes-received": 0,
                    "bytes-transmitted-carry": 1,
                    "bytes-received-carry": 1
                },
                'iface2': {
                    "bytes-transmitted": 1,
                    "bytes-received": 1,
                    "bytes-transmitted-carry": 2,
                    "bytes-received-carry": 2
                }
            }
            self.assertEqual(self.obj.first_net_stats, new_first_stats,
                             'first_net_stats did not change after system counters reset, having previous stats')

    @mock.patch('agent.Telemetry.run')
    def test_get_disks_usage(self, mock_run):
        run = mock.MagicMock()
        # if cmd fails, get a fallbacl list
        run.returncode = 1
        mock_run.return_value = run
        self.assertEqual(['capacity', 'device', 'used'], sorted(self.obj.get_disks_usage()[0].keys()),
                         'Failed to get fallback disk usage when command fails')
        self.assertEqual(len(self.obj.get_disks_usage()), 1,
                         'Fallback disk usage should only have one disk')

        # otherwise
        run.returncode = 0
        run.stdout = '''{
            "blockdevices": [
                {"name":"ram0", "size":4194304, "mountpoint":null, "fsused":null},
                {"name":"loop0", "size":null, "mountpoint":null, "fsused":null},
                {"name":"mmcblk0", "size":31914983424, "mountpoint":null, "fsused":null,
                 "children": [
                     {"name":"mmcblk0p1", "size":2369951744, "mountpoint":null, "fsused":null},
                     {"name":"mmcblk0p7", "size":29239017472, "mountpoint":"/", "fsused":"25306009600"}
                 ]
                 }
            ]
        }'''

        # those without a mountpoint are ignored, so in fact, we only expect one entry from the above devices
        expected = [
            {
                'device': 'mmcblk0p7',
                'capacity': round(int(29239017472)/1024/1024/1024),
                'used': round(25306009600/1024/1024/1024)
            }
        ]
        self.assertEqual(self.obj.get_disks_usage(), expected,
                         'Failed to get disk usage')

    def test_diff(self):
        # new values added, get new value and nothing to delete
        new = {'a': 1, 'b': 2}
        old = {'a': 1}
        expected = ({'b': 2}, set())
        self.assertEqual(self.obj.diff(old, new), expected,
                         'Failed to diff for new values')

        # no changes, nothing to return
        new = {'a': 1}
        old = {'a': 1}
        expected = ({}, set())
        self.assertEqual(self.obj.diff(old, new), expected,
                         'Failed to diff when there are no changes')

        # values modified, return them
        new = {'a': 2}
        old = {'a': 1}
        expected = ({'a': 2}, set())
        self.assertEqual(self.obj.diff(old, new), expected,
                         'Failed to diff for modified values')

        # values have disappeared, return deleted key list
        new = {}
        old = {'a': 1}
        expected = ({}, set('a'))
        self.assertEqual(self.obj.diff(old, new), expected,
                         'Failed to diff for obsolete values (deleted)')

        # all mixed
        new = {'a': 1, 'b': 2, 'c': False, 'd': [1, 2, 3]}
        old = {'a': 1, 'old': 'bye', 'c': True, 'd': [1, 2]}
        expected = ({'b': 2, 'c': False, 'd': [1, 2, 3]}, {'old'})
        self.assertEqual(self.obj.diff(old, new), expected,
                         'Failed to diff')

    @mock.patch.object(Telemetry, 'diff')
    @mock.patch.object(Telemetry, 'get_status')
    def test_update_status(self, mock_get_status, mock_diff):
        previous_status = self.obj.status.copy()
        new_status = {**previous_status, **{'new-value': 'fake-value'}}
        all_status = {**new_status, **{'extra': 'value'}}
        mock_get_status.return_value = (new_status, all_status)
        mock_diff.return_value = ({'new-value': 'fake-value'}, set())

        # make sure the right status is updated and saved
        with mock.patch(self.agent_telemetry_open) as mock_open:
            mock_open.return_value.write.return_value = None
            self.assertIsNone(self.obj.update_status(),
                              'Failed to update status')
            mock_open.assert_called_once_with(self.obj.nuvlabox_status_file, 'w')

        self.assertEqual(self.obj.status, new_status,
                         'NuvlaBox status was not updated in memory')

        minimum_payload_keys = {'current-time', 'id', 'new-value'}
        self.assertEqual(minimum_payload_keys & set(new_status.keys()), minimum_payload_keys,
                         'Failed to set minimum payload for updating nuvlabox-status in Nuvla')

        _, delete_attrs = self.obj.diff(new_status, self.obj.status)
        self.assertEqual(delete_attrs, set(),
                         'Saying there are attrs to delete when there are none')

    @mock.patch('agent.Telemetry.path.exists')
    @mock.patch('agent.Telemetry.stat')
    def test_get_vpn_ip(self, mock_stat, mock_exists):
        # if vpn file does not exist or is empty, get None
        mock_exists.return_value = False
        self.assertIsNone(self.obj.get_vpn_ip(),
                          'Returned VPN IP when VPN file does not exist')
        mock_exists.return_value = True
        mock_stat.return_value.st_size = 0
        self.assertIsNone(self.obj.get_vpn_ip(),
                          'Returned VPN IP when VPN file is empty')

        # otherwise, read the file and return the IP
        mock_stat.return_value.st_size = 1
        with mock.patch(self.agent_telemetry_open, mock.mock_open(read_data='1.1.1.1')):
            self.assertEqual(self.obj.get_vpn_ip(), '1.1.1.1',
                             'Failed to get VPN IP')
