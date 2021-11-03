#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import mock
import requests
import unittest
from tests.utils.fake import Fake, FakeNuvlaApi
import agent.common.NuvlaBoxCommon as NuvlaBoxCommon


class ContainerRuntimeDockerTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.hostfs = '/fake-rootfs'
        self.host_home = '/home/fakeUser'
        self.obj = NuvlaBoxCommon.DockerClient(self.hostfs, self.host_home)
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        self.obj.client.close()
        logging.disable(logging.NOTSET)

    def test_init(self):
        # the Docker client should be set
        self.assertIsInstance(self.obj.client.version(), dict,
                              'Unable to load Docker client')
        self.assertIn('ID', self.obj.client.info(),
                      'Unable to retrieve Docker info')

        # the base class should also have been set
        self.assertEqual(self.obj.job_engine_lite_component, "nuvlabox-job-engine-lite",
                         'Base class of the ContainerRuntime was not properly initialized')
# class NuvlaBoxCommonTestCase(unittest.TestCase):
#
#     def setUp(self):
#         Activate.__bases__ = (Fake.imitate(NuvlaBoxCommon),)
#         self.shared_volume = "mock/path"
#         self.obj = Activate(self.shared_volume)
#         self.api_key_content = '{"api-key": "mock-key", "secret-key": "mock-secret"}'
#         self.obj.activation_flag = 'mock-activation-file'
#         self.obj.nuvlabox_id = "nuvlabox/fake-id"
#         self.obj.nuvla_endpoint = "https://fake-nuvla.io"
#         self.obj.data_volume = self.shared_volume
#         self.obj.context = 'path/to/fake/context/file'
#         logging.disable(logging.CRITICAL)
#
#     def tearDown(self):
#         logging.disable(logging.NOTSET)
#
#     @staticmethod
#     def set_nuvla_api(api_keys):
#         """ Fake the initialization of the Nuvla Api instance """
#         api = FakeNuvlaApi(api_keys)
#         return api
#
#     def test_instantiation(self):
#         self.assertTrue(self.obj.user_info == {}, "Failed to instantiate Activate class instance")
#
#     @mock.patch.object(Activate, 'read_json_file')
#     @mock.patch.object(Activate, 'write_json_to_file')
#     @mock.patch.object(Activate, 'get_api_keys')
#     @mock.patch.object(Activate, 'get_operational_status')
#     def test_activation_is_possible(self, mock_get_op_status, mock_get_api_keys, mock_write_file, mock_read_file):
#         # activation is not possible because NuvlaBox is not ready/operational
#         mock_get_op_status.return_value = 'UNKNOWN'
#         self.assertEqual(self.obj.activation_is_possible(), (False, {}),
#                          'Activation unable to cope with UNKNOWN operational status')
#
#         mock_get_op_status.return_value = 'OPERATIONAL'
#         # if there's no file and no env, then activation should go through
#         mock_get_api_keys.return_value = (None, None)
#         mock_read_file.side_effect = FileNotFoundError
#         self.assertEqual(self.obj.activation_is_possible(), (True, {}),
#                          'Activation not possible when it should be')
#
#         # activation is not possible, because even though files does not exist, API keys are in env
#         mock_write_file.return_value = True
#         mock_get_api_keys.return_value = (json.loads(self.api_key_content)['api-key'],
#                                           json.loads(self.api_key_content)['secret-key'])
#         self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
#                          'Cannot read existing activation file with API key credentials')
#         self.assertTrue(mock_write_file.called,
#                         'Could not save API keys from env into file')
#
#         # activation is not possible because NuvlaBox has already been activated - there's a file
#         mock_read_file.reset_mock(return_value=True, side_effect=True)
#         mock_read_file.return_value = json.loads(self.api_key_content)
#         # with mock.patch("agent.Activate.open", mock.mock_open(read_data=self.api_key_content)):
#         self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
#                          'Cannot read existing activation file with API key credentials')
#
#     @mock.patch.object(Activate, 'shell_execute')
#     @mock.patch.object(Activate, 'write_json_to_file')
#     @mock.patch.object(Activate, 'api')
#     def test_activate(self, mock_api, mock_write_file, mock_shell_exec):
#         # successful activation will return the API keys for the NuvlaBox
#         mock_api.return_value = self.set_nuvla_api(json.loads(self.api_key_content))
#         mock_write_file.return_value = True
#         self.assertEqual(self.obj.activate(), json.loads(self.api_key_content),
#                          'Unable to activate the NuvlaBox')
#         # and because it was successful, the API keys have been written to a file
#         mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))
#
#         # if there's an SSLError while activating, then systemd-timesyncd should take place
#         mock_shell_exec.return_value = True
#         mock_api.side_effect = requests.exceptions.SSLError
#         self.assertRaises(requests.exceptions.SSLError, self.obj.activate)
#         self.assertTrue(mock_shell_exec.called,
#                         'requests.exceptions.SSLError was not caught during NuvlaBox activation')
#         # there hasn't been a new attempt to write the api keys into the file
#         mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))
#
#         # if there's a connection error, then an exception must be thrown
#         mock_api.side_effect = requests.exceptions.ConnectionError
#         self.assertRaises(requests.exceptions.ConnectionError, self.obj.activate)
#         # ensure neither the write function nor the shell_exec have been called a second time
#         mock_shell_exec.assert_called_once()
#         mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))
#
#     @mock.patch.object(Activate, 'write_json_to_file')
#     @mock.patch.object(Activate, 'read_json_file')
#     def test_create_nb_document(self, mock_read_json_file, mock_write_to_file):
#         # if context file does not exist, the old NB resource should be empty
#         mock_read_json_file.side_effect = FileNotFoundError
#         mock_write_to_file.return_value = None
#         self.assertEqual(self.obj.create_nb_document_file({'foo': 'bar'}), {},
#                          'Returned an old NuvlaBox resource when there should not be one')
#         mock_read_json_file.assert_called_once()
#         mock_write_to_file.assert_called_once()
#
#         # if there is a context file already, its content will be returned as the old NuvlaBox resource context
#         old_nuvlabox_context = {'id': 'nuvlabox/fake-old'}
#         mock_read_json_file.reset_mock(side_effect=True)
#         mock_write_to_file.reset_mock()
#         mock_read_json_file.return_value = old_nuvlabox_context
#         self.assertEqual(self.obj.create_nb_document_file({'foo': 'bar'}), old_nuvlabox_context,
#                          'Unable to get old NuvlaBox context when creating new NB document')
#         mock_write_to_file.assert_called_once()
#
#     @mock.patch.object(Activate, 'commission_vpn')
#     def test_vpn_commission_if_needed(self, mock_commission_vpn):
#         old_nuvlabox_resource = {'id': self.obj.nuvlabox_id}
#         new_nuvlabox_resource = {**old_nuvlabox_resource, **{'vpn-server-id': 'infrastructure-servive/fake-vpn'}}
#
#         mock_commission_vpn.return_value = None
#
#         # if 'vpn-server-id' has not changed, then VPN commissioning will not be invoked
#         self.obj.vpn_commission_if_needed(old_nuvlabox_resource, old_nuvlabox_resource)
#         mock_commission_vpn.assert_not_called()
#
#         # but if 'vpn-server-id' changes, then VPN commissioning takes place
#         self.obj.vpn_commission_if_needed(new_nuvlabox_resource, old_nuvlabox_resource)
#         mock_commission_vpn.assert_called_once()
#
#     @mock.patch.object(Activate, 'api')
#     def test_get_nuvlabox_info(self, mock_api):
#         mock_api.return_value = self.set_nuvla_api(json.loads(self.api_key_content))
#
#         # Nuvla should return the NuvlaBox resource
#         returned_nuvlabox_resource = self.obj.get_nuvlabox_info()
#         self.assertIsInstance(returned_nuvlabox_resource, dict)
#         self.assertEqual(self.obj.nuvlabox_id, returned_nuvlabox_resource.get('id'),
#                          'Did not get the expected NuvlaBox resource')
#         mock_api.assert_called_once()
#
#     @mock.patch.object(Activate, 'create_nb_document_file')
#     @mock.patch.object(Activate, 'get_nuvlabox_info')
#     @mock.patch.object(Activate, 'authenticate')
#     def test_update_nuvlabox_resource(self, mock_authenticate, mock_get_nuvlabox_info, mock_create_nb_doc):
#         self.obj.user_info = json.loads(self.api_key_content)
#         mock_authenticate.return_value = self.set_nuvla_api(self.obj.user_info)
#         old_nuvlabox_resource = {'id': self.obj.nuvlabox_id}
#         new_nuvlabox_resource = {**old_nuvlabox_resource, **{'new-attr': True}}
#         mock_get_nuvlabox_info.return_value = new_nuvlabox_resource
#         mock_create_nb_doc.return_value = old_nuvlabox_resource
#
#         # when called, it shall get the NB resource from Nuvla,
#         # overwrite the existing NB doc,
#         # and return both old and new NB resources
#         self.assertEqual(self.obj.update_nuvlabox_resource(), (new_nuvlabox_resource, old_nuvlabox_resource),
#                          'Failed to update NuvlaBox resource: unexpected "new" and "old" NB resources')
