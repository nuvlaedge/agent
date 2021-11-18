#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from agent.Telemetry import ContainerMonitoring
import json
import logging
import mock
import queue
import requests
import unittest
import tests.utils.fake as fake
import agent.common.NuvlaBoxCommon as NuvlaBoxCommon
from threading import Thread


class ContainerMonitoringTestCase(unittest.TestCase):

    def setUp(self):
        ContainerMonitoring.__bases__ = (fake.Fake.imitate(Thread),)
        self.container_runtime = fake.Fake.imitate(NuvlaBoxCommon.ContainerRuntimeClient)
        self.q = queue.Queue()
        self.obj = ContainerMonitoring(self.q, self.container_runtime)
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_init(self):
        self.assertIsInstance(self.obj.log, type(logging),
                              'Failed to instantiate logging for container monitoring')
        self.assertIsInstance(self.obj.q, queue.Queue,
                              'Failed to instantiate queue')
        self.assertIsNotNone(self.obj.container_runtime.collect_container_metrics,
                             'Failed to instantiate container runtime')

    @mock.patch('queue.Queue.put')
    @mock.patch('time.sleep', side_effect=InterruptedError)
    def test_run(self, mock_sleep, mock_put):
        self.obj.container_runtime.collect_container_metrics.return_value = None
        mock_put.return_value = None
        # if save_to is not defined, file is not written
        with mock.patch('agent.Telemetry.open') as mock_open:
            self.assertRaises(InterruptedError, self.obj.run)
            mock_open.assert_not_called()
            mock_sleep.assert_called_once()

        # if save_to is defined, file is written
        self.obj.save_to = 'mock-file'
        with mock.patch('agent.Telemetry.open') as mock_open:
            mock_open.return_value.write.return_value = None
            self.assertRaises(InterruptedError, self.obj.run)
            mock_open.assert_called_once_with('mock-file', 'w')