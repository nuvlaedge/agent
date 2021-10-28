#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from agent.Activate import Activate
import json
import mock
import requests
import unittest
from tests.utils.fake import Fake
from agent.common.NuvlaBoxCommon import NuvlaBoxCommon


class ActivateTestCase(unittest.TestCase):

    def setUp(self):
        Activate.__bases__ = (Fake.imitate(NuvlaBoxCommon),)
        self.shared_volume = "mock/path"
        self.obj = Activate(self.shared_volume)
        self.api_key_content = '{"api-key": "mock-key", "secret-key": "mock-secret"}'
        self.obj.activation_flag = 'mock-activation-file'
        self.obj.nuvlabox_id = "nuvlabox/fake-id"
        self.obj.nuvla_endpoint = "https://fake-nuvla.io"

    def test_instantiation(self):
        self.assertTrue(self.obj.user_info == {}, "Failed to instantiate Activate class instance")

    @mock.patch.object(Activate, 'read_json_file')
    @mock.patch.object(Activate, 'write_json_to_file')
    @mock.patch.object(Activate, 'get_api_keys')
    @mock.patch.object(Activate, 'get_operational_status')
    def test_activation_is_possible(self, mock_get_op_status, mock_get_api_keys, mock_write_file, mock_read_file):
        # activation is not possible because NuvlaBox is not ready/operational
        mock_get_op_status.return_value = 'UNKNOWN'
        self.assertEqual(self.obj.activation_is_possible(), (False, {}),
                         'Activation unable to cope with UNKNOWN operational status')

        mock_get_op_status.return_value = 'OPERATIONAL'
        # if there's no file and no env, then activation should go through
        mock_get_api_keys.return_value = (None, None)
        mock_read_file.side_effect = FileNotFoundError
        self.assertEqual(self.obj.activation_is_possible(), (True, {}),
                         'Activation not possible when it should be')

        # activation is not possible, because even though files does not exist, API keys are in env
        mock_write_file.return_value = True
        mock_get_api_keys.return_value = (json.loads(self.api_key_content)['api-key'],
                                          json.loads(self.api_key_content)['secret-key'])
        self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
                         'Cannot read existing activation file with API key credentials')
        self.assertTrue(mock_write_file.called,
                        'Could not save API keys from env into file')

        # activation is not possible because NuvlaBox has already been activated - there's a file
        mock_read_file.reset_mock(return_value=True, side_effect=True)
        mock_read_file.return_value = json.loads(self.api_key_content)
        # with mock.patch("agent.Activate.open", mock.mock_open(read_data=self.api_key_content)):
        self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
                         'Cannot read existing activation file with API key credentials')

    @mock.patch.object(Activate, 'shell_execute')
    @mock.patch.object(Activate, 'write_json_to_file')
    @mock.patch.object(Activate, 'api')
    def test_activate(self, mock_api, mock_write_file, mock_shell_exec):
        class Api(object):
            def __init__(self, reference_api_keys):
                self.api_keys = reference_api_keys

            def _cimi_post(self, nuvlabox_id):
                return self.api_keys

        def setApi(api_keys):
            api = Api(api_keys)
            return api

        # succesfull activation will return the API keys for the NuvlaBox
        mock_api.return_value = setApi(json.loads(self.api_key_content))
        mock_write_file.return_value = True
        self.assertEqual(self.obj.activate(), json.loads(self.api_key_content),
                         'Unable to activate the NuvlaBox')
        # and because it was successful, the API keys have been written to a file
        mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))

        # if there's an SSLError while activating, then systemd-timesyncd should take place
        mock_shell_exec.return_value = True
        mock_api.side_effect = requests.exceptions.SSLError
        self.assertRaises(requests.exceptions.SSLError, self.obj.activate)
        self.assertTrue(mock_shell_exec.called,
                        'requests.exceptions.SSLError was not caught during NuvlaBox activation')
        # there hasn't been a new attempt to write the api keys into the file
        mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))

        # if there's a connection error, then an exception must be thrown
        mock_api.side_effect = requests.exceptions.ConnectionError
        self.assertRaises(requests.exceptions.ConnectionError, self.obj.activate)
        # ensure neither the write function nor the shell_exec have been called a second time
        mock_shell_exec.assert_called_once()
        mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))






