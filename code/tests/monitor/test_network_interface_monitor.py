# -*- coding: utf-8 -*-
import unittest
from random import SystemRandom
from typing import List, Dict, Any

import requests
from docker import errors as docker_err
from mock import Mock, mock_open, patch

from agent.monitor.components import network_interface_monitor as monitor
from agent.monitor.data.network_data import NetworkInterface
from agent.monitor.edge_status import EdgeStatus


def generate_random_ip_address():
    rand_bits = SystemRandom().getrandbits(8)
    it_str: List[str] = [str(rand_bits) for _ in range(4)]
    return ".".join(it_str)


class TestNetworkIfaceMonitor(unittest.TestCase):

    # -------------------- Public data tests -------------------- #
    def test_set_public_data(self):
        status = Mock()
        status.iface_data = None
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("file", Mock(), status)
        self.assertIsNone(test_ip_monitor.data.public.ip)
        test_ip_monitor.set_public_data()
        self.assertIsNotNone(test_ip_monitor.data.public.ip)

        # Test exception clause
        status.iface_data = None
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("file", Mock(), Mock())
        test_ip_monitor._REMOTE_IPV4_API = "empty"
        with self.assertRaises(requests.exceptions.MissingSchema):
            test_ip_monitor.set_public_data()

    def test_set_public_data_should_raise_timeout(self):
        # Test timeout
        with patch('requests.get') as get:
            get.side_effect = requests.Timeout
            test_ip_monitor: monitor.NetworkIfaceMonitor = \
                monitor.NetworkIfaceMonitor("file", Mock(), EdgeStatus())
            test_ip_monitor.set_public_data()
            self.assertIsNone(test_ip_monitor.data.public.ip)

    # -------------------- Local data tests -------------------- #
    def test_parse_host_ip_json(self):
        # Base test
        it_ip: str = generate_random_ip_address()
        test_attribute: Dict[str, Any] = {
            "dev": "eth0",
            "prefsrc": it_ip
        }
        status = Mock()
        status.iface_data = None
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("file", Mock(), status)
        expected_result: NetworkInterface = \
            NetworkInterface(iface_name="eth0", ip=it_ip)
        self.assertEqual(test_ip_monitor.parse_host_ip_json(test_attribute),
                         expected_result)

        # Non-complete attributes tests
        test_attribute.pop("dev")
        self.assertIsNone(test_ip_monitor.parse_host_ip_json(test_attribute))

        test_attribute["dev"] = "eth0"
        test_attribute.pop("prefsrc")
        self.assertIsNone(test_ip_monitor.parse_host_ip_json(test_attribute))

    def test_gather_host_route(self):
        # Test Raise exception
        it_1 = Mock()
        it_1.client.containers.run.side_effect = docker_err.APIError("Not found")
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", it_1, EdgeStatus())
        self.assertIsNone(test_ip_monitor.gather_host_ip_route())

        # Decode test
        runtime_mock = Mock()
        runtime_mock.client.containers.run.return_value = b'{}'
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", runtime_mock, EdgeStatus())
        self.assertIsInstance(test_ip_monitor.gather_host_ip_route(), str)

        runtime_mock.client.containers.run.return_value = '{}'
        with self.assertRaises(AttributeError):
            test_ip_monitor.gather_host_ip_route()

    def test_set_local_data(self):
        status = Mock()
        status.iface_data = None
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", Mock(), status)
        test_ip_monitor.runtime_client.client.containers.run.return_value = b"{[]}"
        test_ip_monitor.set_local_data()
        self.assertFalse(test_ip_monitor.data.local)

        # Test readable route
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", Mock(), EdgeStatus())
        test_ip_monitor.is_skip_route = Mock(return_value=True)
        test_ip_monitor.gather_host_ip_route = Mock(return_value='{}')
        test_ip_monitor.set_local_data()
        self.assertEqual(test_ip_monitor.data.local, {})

        with patch('json.loads') as json_dict:
            test_ip_monitor: monitor.NetworkIfaceMonitor = \
                monitor.NetworkIfaceMonitor("", Mock(), EdgeStatus())
            test_ip_monitor.is_skip_route = Mock(return_value=False)
            test_ip_monitor.gather_host_ip_route = Mock(return_value='{}')
            it_address: str = generate_random_ip_address()
            json_dict.return_value = [{'dst': 'default',
                                       'dev': 'eth0',
                                       'prefsrc': it_address}]
            test_ip_monitor.set_local_data()
            self.assertEqual(test_ip_monitor.data.local['eth0'].ip, it_address)

    def test_is_skip_route(self):
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", Mock(), EdgeStatus())

        self.assertTrue(test_ip_monitor.is_skip_route({}))

        self.assertFalse(test_ip_monitor.is_skip_route(
            {'dst': generate_random_ip_address()}))

        test_ip_monitor.data.local = {'eth0': ''}
        self.assertTrue(test_ip_monitor.is_skip_route({'dev': 'eth0'}))

        self.assertFalse(test_ip_monitor.is_skip_route({
            'dst': generate_random_ip_address(),
            'dev': 'eth1'}))

    # -------------------- VPN data tests -------------------- #
    def test_set_vpn_data(self):
        vpn_file = Mock()
        status = Mock()
        status.iface_data = None
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor(vpn_file, Mock(), status)
        built_open: str = "builtins.open"
        it_ip: str = generate_random_ip_address()
        with patch("os.stat") as stat_mock, \
                patch("os.path.exists") as exists_mock:
            exists_mock.return_value = True
            stat_mock.return_value = Mock(st_size=30)

            with patch(built_open, mock_open(read_data=it_ip)):
                test_ip_monitor.set_vpn_data()
                self.assertEqual(str(test_ip_monitor.data.vpn.ip), it_ip)

        with patch("os.stat") as stat_mock, \
                patch("os.path.exists") as exists_mock:
            exists_mock.return_value = True
            stat_mock.return_value = Mock(st_size=0)

            with patch(built_open, mock_open(read_data="")):
                test_ip_monitor.data.vpn = NetworkInterface(iface_name="vpn")
                test_ip_monitor.set_vpn_data()
                self.assertIsNone(test_ip_monitor.data.vpn.ip)

    # -------------------- Swarm data tests -------------------- #
    def test_set_swarm_data(self):
        runtime_mock = Mock()
        r_ip: str = generate_random_ip_address()
        status = Mock()
        status.iface_data = None
        runtime_mock.get_api_ip_port.return_value = (r_ip, 0)
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", runtime_mock, status)
        test_ip_monitor.set_swarm_data()
        self.assertEqual(str(test_ip_monitor.data.swarm.ip), r_ip)

        runtime_mock.get_api_ip_port.return_value = (None, None)
        test_ip_monitor.set_swarm_data()
        self.assertIsNone(test_ip_monitor.data.swarm)

        runtime_mock.get_api_ip_port.return_value = None
        with self.assertRaises(TypeError):
            test_ip_monitor.set_swarm_data()

    @patch('agent.monitor.components.network_interface_monitor.'
           'NetworkIfaceMonitor.set_public_data')
    @patch('agent.monitor.components.network_interface_monitor.'
           'NetworkIfaceMonitor.set_local_data')
    @patch('agent.monitor.components.network_interface_monitor.'
           'NetworkIfaceMonitor.set_vpn_data')
    @patch('agent.monitor.components.network_interface_monitor.'
           'NetworkIfaceMonitor.set_swarm_data')
    def test_update_data(self, pub, local, vpn, swarm):
        runtime_mock = Mock()
        # r_ip: str = generate_random_ip_address()
        status = Mock()
        status.iface_data = None
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", runtime_mock, status)
        test_ip_monitor.update_data()

        # Check public is called
        self.assertEqual(pub.call_count, 1)
        self.assertEqual(local.call_count, 1)
        self.assertEqual(vpn.call_count, 1)
        self.assertEqual(swarm.call_count, 1)

    def test_get_data(self):
        runtime_mock = Mock()
        status = Mock()
        status.iface_data = None
        test_ip_monitor: monitor.NetworkIfaceMonitor = \
            monitor.NetworkIfaceMonitor("", runtime_mock, status)

        # No data- return none
        self.assertIsNone(test_ip_monitor.get_data())
        test_ip_monitor.data.vpn = Mock()
        test_ip_monitor.data.vpn.ip = "VPN_IP"
        self.assertIsNotNone(test_ip_monitor.get_data())

        test_ip_monitor.data.public.ip = "PUB"
        self.assertEqual('VPN_IP', test_ip_monitor.get_data())

        test_ip_monitor.data.public.ip = "PUB"
        test_ip_monitor.data.vpn = None
        self.assertEqual("PUB", test_ip_monitor.get_data())
