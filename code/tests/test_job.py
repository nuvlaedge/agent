#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import mock
import unittest
from tests.utils.fake import Fake
from agent.job import Job
from agent.common.nuvlaedge_common import NuvlaEdgeCommon


class JobTestCase(unittest.TestCase):

    def setUp(self):
        Job.__bases__ = (Fake.imitate(NuvlaEdgeCommon),)
        self.shared_volume = "mock/path"
        self.job_id = "job/fake-id"
        self.job_engine_lite_image = 'job-lite'
        with mock.patch('agent.job.Job.check_job_is_running') as mock_job_is_running:
            mock_job_is_running.return_value = False
            self.obj = Job(self.shared_volume, self.job_id, self.job_engine_lite_image)
        # monkeypatches
        self.obj.container_runtime = mock.MagicMock()
        self.obj.activation_flag = '.activation'
        self.obj.nuvla_endpoint_insecure = False
        self.obj.nuvla_endpoint = 'fake.nuvla.io'
        ###
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_init(self):
        # according to setUp, do_nothing is False and job_id should have been cleaned
        self.assertFalse(self.obj.do_nothing,
                         'Failed to check if job is running at class instantiation')
        self.assertEqual(self.obj.job_id_clean, self.job_id.replace('/', '-'),
                         'Failed to convert job ID into container-friendly name')

        # also make sure NuvlaEdgeCommon has been inherited
        self.assertIsNotNone(self.obj.api(),
                             'NuvlaEdgeCommon was not inherited properly')

    def test_check_job_is_running(self):
        self.obj.container_runtime.is_nuvla_job_running.return_value = False
        # simply return the output from the container_runtime function
        self.assertFalse(self.obj.check_job_is_running(),
                         'Failed to check job is NOT running')

        self.obj.container_runtime.is_nuvla_job_running.return_value = True
        self.assertTrue(self.obj.check_job_is_running(),
                        'Failed to check job is running')

    def test_launch(self):
        self.obj.container_runtime.launch_job.return_value = None
        # without API keys, we can't launch and return none
        with mock.patch('agent.job.open') as mock_open:
            mock_open.side_effect = FileNotFoundError
            self.assertIsNone(self.obj.launch(),
                              'Tried to launch job even though API keys could not be found')

        self.obj.container_runtime.launch_job.assert_not_called()
        # otherwise, launch the job
        with mock.patch('agent.job.open', mock.mock_open(read_data='{"api-key": "", "secret-key": ""}')):
            self.assertIsNone(self.obj.launch(),
                              'Failed to launch job')

        self.obj.container_runtime.launch_job.assert_called_once_with(self.obj.job_id, self.obj.job_id_clean,
                                                                      self.obj.nuvla_endpoint,
                                                                      self.obj.nuvla_endpoint_insecure,
                                                                      "", "", self.obj.job_engine_lite_image)
