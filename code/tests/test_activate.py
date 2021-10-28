#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from agent.Activate import Activate
import json
import mock
import unittest
from tests.utils.fake import Fake
from agent.common.NuvlaBoxCommon import NuvlaBoxCommon


class ActivateTestCase(unittest.TestCase):

    def setUp(self):
        Activate.__bases__ = (Fake.imitate(NuvlaBoxCommon),)
        self.shared_volume = "mock/path"
        self.obj = Activate(self.shared_volume)
        self.api_key_content = '{"api-key": "mock-key", "secret-key": "mock-secret"}'

    def test_instantiation(self):
        self.assertTrue(self.obj.user_info == {}, "Failed to instantiate Activate class instance")

    @mock.patch.object(Activate, 'write_json_to_file')
    @mock.patch.object(Activate, 'get_api_keys')
    @mock.patch.object(Activate, 'get_operational_status')
    def test_activation_is_possible(self, mock_get_op_status, mock_get_api_keys, mock_write_file):
        self.obj = Activate(self.shared_volume)

        # activation is not possible because NuvlaBox is not ready/operational
        mock_get_op_status.return_value = 'UNKNOWN'
        self.assertEqual(self.obj.activation_is_possible(), (False, {}),
                         'Activation unable to cope with UNKNOWN operational status')

        self.obj.activation_flag = 'mock-activation-file'
        mock_get_op_status.return_value = 'OPERATIONAL'
        # activation is not possible because NuvlaBox has already been activated
        with mock.patch("agent.Activate.open", mock.mock_open(read_data=self.api_key_content)):
            self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
                             'Cannot read existing activation file with API key credentials')

        # activation is not possible, because even though files does not exist, API keys are in env
        mock_write_file.return_value = True
        mock_get_api_keys.return_value = (json.loads(self.api_key_content)['api-key'],
                                          json.loads(self.api_key_content)['secret-key'])
        self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
                         'Cannot read existing activation file with API key credentials')
        self.assertTrue(mock_write_file.called,
                        'Could not save API keys from env into file')

        # if there's no file and no env, then activation should go through
        self.obj.user_info = {}
        mock_get_api_keys.return_value = (None, None)
        self.assertEqual(self.obj.activation_is_possible(), (True, {}),
                         'Activation not possible when it should be')





