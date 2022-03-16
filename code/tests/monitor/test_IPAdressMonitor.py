#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import unittest
from pydantic.error_wrappers import ValidationError
from mock import Mock, mock_open, patch
from agent.monitor.IPAddressMonitor import IPAddressTelemetry, NetworkTelemetryStructure, NetworkInterface
from typing import Dict, Any
import os


class TestIPAddressMonitor(unittest.TestCase):

    def test_set_public_data(self):
        test_ip_monitor: IPAddressTelemetry = IPAddressTelemetry("file", Mock())
        self.assertIsNone(test_ip_monitor.custom_data.public.ip)
        test_ip_monitor.set_public_data()
        self.assertIsNotNone(test_ip_monitor.custom_data.public.ip)

    def test_parse_host_ip_json(self):
        # Base test
        test_attribute: Dict[str, Any] = {
            "dev": "eth0",
            "prefsrc": "192.168.0.1"
        }
        test_ip_monitor: IPAddressTelemetry = IPAddressTelemetry("file", Mock())
        expected_result: NetworkInterface = NetworkInterface(iface_name="eth0", ip="192.168.0.1")
        self.assertEqual(test_ip_monitor.parse_host_ip_json(test_attribute), expected_result)

        # Non-complete attributes tests
        test_attribute.pop("dev")
        self.assertIsNone(test_ip_monitor.parse_host_ip_json(test_attribute))

        test_attribute["dev"] = "eth0"
        test_attribute.pop("prefsrc")
        self.assertIsNone(test_ip_monitor.parse_host_ip_json(test_attribute))

    def test_set_local_data(self):
        test_ip_monitor: IPAddressTelemetry = IPAddressTelemetry("", Mock())
        test_ip_monitor.runtime_client.client.containers.run.return_value = b"{[]}"
        test_ip_monitor.set_local_data()
        self.assertFalse(test_ip_monitor.custom_data.local)

    def test_set_vpn_data(self):
        vpn_file = Mock()
        test_ip_monitor: IPAddressTelemetry = IPAddressTelemetry(vpn_file, Mock())
        built_open: str = "builtins.open"
        with patch("os.stat") as stat_mock, \
                patch("os.path.exists") as exists_mock:
            exists_mock.return_value = True
            stat_mock.return_value = Mock(st_size=30)

            with patch(built_open, mock_open(read_data="192.168.0.1")):
                test_ip_monitor.set_vpn_data()
                self.assertEqual(str(test_ip_monitor.custom_data.vpn.ip), "192.168.0.1")

            with patch(built_open, mock_open(read_data="NOTANIP")):
                with self.assertRaises(ValidationError):
                    test_ip_monitor.set_vpn_data()

        with patch("os.stat") as stat_mock, \
                patch("os.path.exists") as exists_mock:
            exists_mock.return_value = True
            stat_mock.return_value = Mock(st_size=0)

            with patch(built_open, mock_open(read_data="")):
                test_ip_monitor.custom_data.vpn = NetworkInterface(iface_name="vpn")
                test_ip_monitor.set_vpn_data()
                self.assertIsNone(test_ip_monitor.custom_data.vpn.ip)

    def test_set_swarm_data(self):
        ...
