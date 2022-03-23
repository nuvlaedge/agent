#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from typing import List
from random import SystemRandom
from pydantic.error_wrappers import ValidationError
from mock import Mock, mock_open, patch
from agent.monitor.components import network_interface_monitor as net_mon
from agent.monitor.data.network_data import NetworkInterface
from typing import Dict, Any


def generate_random_ip_address():
    rand_bits = SystemRandom().getrandbits(8)
    it_str: List[str] = [str(rand_bits) for _ in range(4)]
    return ".".join(it_str)


class TestIPAddressMonitor(unittest.TestCase):

    def test_set_public_data(self):
        status = Mock()
        status.iface_data = None
        test_ip_monitor: net_mon.NetworkIfaceMonitor = \
            net_mon.NetworkIfaceMonitor("file", Mock(), status)
        self.assertIsNone(test_ip_monitor.data.public.ip)
        test_ip_monitor.set_public_data()
        self.assertIsNotNone(test_ip_monitor.data.public.ip)

    def test_parse_host_ip_json(self):
        # Base test
        it_ip: str = generate_random_ip_address()
        test_attribute: Dict[str, Any] = {
            "dev": "eth0",
            "prefsrc": it_ip
        }
        status = Mock()
        status.iface_data = None
        test_ip_monitor: net_mon.NetworkIfaceMonitor = \
            net_mon.NetworkIfaceMonitor("file", Mock(), status)
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

    def test_set_local_data(self):
        status = Mock()
        status.iface_data = None
        test_ip_monitor: net_mon.NetworkIfaceMonitor = \
            net_mon.NetworkIfaceMonitor("", Mock(), status)
        test_ip_monitor.runtime_client.client.containers.run.return_value = b"{[]}"
        test_ip_monitor.set_local_data()
        self.assertFalse(test_ip_monitor.data.local)

    def test_set_vpn_data(self):
        vpn_file = Mock()
        status = Mock()
        status.iface_data = None
        test_ip_monitor: net_mon.NetworkIfaceMonitor = \
            net_mon.NetworkIfaceMonitor(vpn_file, Mock(), status)
        built_open: str = "builtins.open"
        it_ip: str = generate_random_ip_address()
        with patch("os.stat") as stat_mock, \
                patch("os.path.exists") as exists_mock:
            exists_mock.return_value = True
            stat_mock.return_value = Mock(st_size=30)

            with patch(built_open, mock_open(read_data=it_ip)):
                test_ip_monitor.set_vpn_data()
                self.assertEqual(str(test_ip_monitor.data.vpn.ip), it_ip)

            with patch(built_open, mock_open(read_data="NOTANIP")):
                with self.assertRaises(ValidationError):
                    test_ip_monitor.set_vpn_data()

        with patch("os.stat") as stat_mock, \
                patch("os.path.exists") as exists_mock:
            exists_mock.return_value = True
            stat_mock.return_value = Mock(st_size=0)

            with patch(built_open, mock_open(read_data="")):
                test_ip_monitor.data.vpn = NetworkInterface(iface_name="vpn")
                test_ip_monitor.set_vpn_data()
                self.assertIsNone(test_ip_monitor.data.vpn.ip)

    def test_set_swarm_data(self):
        runtime_mock = Mock()
        r_ip: str = generate_random_ip_address()
        status = Mock()
        status.iface_data = None
        runtime_mock.get_api_ip_port.return_value = (r_ip, 0)
        test_ip_monitor: net_mon.NetworkIfaceMonitor = \
            net_mon.NetworkIfaceMonitor("", runtime_mock, status)
        test_ip_monitor.set_swarm_data()
        self.assertEqual(str(test_ip_monitor.data.swarm.ip), r_ip)

        it_ip = r_ip.split(".")
        runtime_mock.get_api_ip_port.return_value = (".".join(it_ip[0:-1]), 0)
        with self.assertRaises(ValidationError):
            test_ip_monitor.set_swarm_data()

        runtime_mock.get_api_ip_port.return_value = (None, None)
        test_ip_monitor.set_swarm_data()
        self.assertIsNone(test_ip_monitor.data.swarm)

        runtime_mock.get_api_ip_port.return_value = None
        with self.assertRaises(TypeError):
            test_ip_monitor.set_swarm_data()
