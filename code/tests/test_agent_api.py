#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import agent
import json
import logging
import mock
import nuvla
import requests
import unittest
from tests.utils.fake import Fake, FakeNuvlaApi
from agent.common.NuvlaBoxCommon import NuvlaBoxCommon


with mock.patch.object(agent.common.NuvlaBoxCommon, 'NuvlaBoxCommon') as mock_nb_common:
    mock_nb_common.return_value = Fake.imitate(NuvlaBoxCommon)
    from agent import AgentApi


class AgentApiTestCase(unittest.TestCase):

    def setUp(self):
        self.peripheral_filepath = 'mock/peripheral/path'
        self.peripheral_content = {'id': 'nuvlabox-peripheral/fake-peripheral', 'foo': 'bar'}
        AgentApi.NB.nuvlabox_id = 'nuvlabox/fake-id'
        AgentApi.NB.peripherals_dir = 'fake/path'
        self.api_key = {"api-key": "mock-key", "secret-key": "mock-secret"}
        self.peripheral_identifier = 'valid identifier'
        self.valid_payload = {'identifier': self.peripheral_identifier}
        self.incomplete_payload = {'not-identifier': 'missing-identifier'}
        self.malformed_payload = 'wrong-type'
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @mock.patch('agent.AgentApi.os')
    def test_local_peripheral_exists(self, mock_os):
        # if file path exists, then we should get True
        mock_os.path.exists.return_value = True
        self.assertTrue(AgentApi.local_peripheral_exists(self.peripheral_filepath))

        # but if it does not exist, we expect False
        mock_os.path.exists.return_value = False
        self.assertFalse(AgentApi.local_peripheral_exists(self.peripheral_filepath))

    @mock.patch('agent.AgentApi.NB.write_json_to_file')
    def test_local_peripheral_save(self, mock_write_to_file):
        mock_write_to_file.return_value = None
        # when trying to save a peripheral, the write fn should be called, with no errors

        AgentApi.local_peripheral_save(self.peripheral_filepath, self.peripheral_content)
        mock_write_to_file.assert_called_once_with(self.peripheral_filepath, self.peripheral_content)

    @mock.patch('agent.AgentApi.NB.read_json_file')
    @mock.patch('agent.AgentApi.NB.write_json_to_file')
    def test_local_peripheral_update(self, mock_write_to_file, mock_read_file):
        new_peripheral = {**self.peripheral_content, **{'new-var': 'value'}}
        # if unable to read file, then exception is thrown and 'write' never happens
        mock_read_file.side_effect = FileNotFoundError
        self.assertRaises(FileNotFoundError, AgentApi.local_peripheral_update,
                          self.peripheral_filepath, new_peripheral)
        mock_write_to_file.assert_not_called()
        mock_read_file.assert_called_once_with(self.peripheral_filepath)

        # if peripheral file exists, read it, update it, and write new content
        mock_read_file.reset_mock(side_effect=True)
        mock_read_file.return_value = self.peripheral_content
        mock_write_to_file.return_value = None
        AgentApi.local_peripheral_update(self.peripheral_filepath, new_peripheral)
        mock_write_to_file.assert_called_once_with(self.peripheral_filepath, new_peripheral)

    @mock.patch('agent.AgentApi.NB.read_json_file')
    def test_local_peripheral_get_identifier(self, mock_read_file):
        # if there's no peripheral file, we get None
        mock_read_file.side_effect = FileNotFoundError
        self.assertIs(AgentApi.local_peripheral_get_identifier(self.peripheral_filepath), None,
                      'Should have returned None because peripheral does not exist')

        # otherwise, returns the peripheral ID
        mock_read_file.reset_mock(side_effect=True)
        mock_read_file.return_value = self.peripheral_content
        self.assertEqual(AgentApi.local_peripheral_get_identifier(self.peripheral_filepath),
                         self.peripheral_content['id'],
                         'Failed to give back right peripheral ID')

    @mock.patch('agent.AgentApi.NB.get_nuvlabox_version')
    def test_sanitize_peripheral_payload(self, mock_get_version):
        # if payload is broken, an exception should be thrown
        self.assertRaises(TypeError, AgentApi.sanitize_peripheral_payload, self.malformed_payload)
        self.assertRaises(KeyError, AgentApi.sanitize_peripheral_payload, self.incomplete_payload)

        # if payload is correct, it will validate it and complete it with missing information
        mock_get_version.return_value = 2
        AgentApi.sanitize_peripheral_payload(self.valid_payload)
        self.assertIn('version', self.valid_payload,
                      'Peripheral payload was not completed with NuvlaBox Engine version')
        self.assertIn('parent', self.valid_payload,
                      'Peripheral payload was not completed with NuvlaBox resource parent ID')
        self.assertEqual(self.valid_payload.get('identifier'), self.peripheral_identifier)

    @mock.patch('agent.AgentApi.local_peripheral_save')
    @mock.patch('agent.AgentApi.modify')
    @mock.patch('requests.Response')
    @mock.patch('agent.AgentApi.NB.api')
    @mock.patch('agent.AgentApi.local_peripheral_exists')
    @mock.patch('agent.AgentApi.sanitize_peripheral_payload')
    def test_post(self, mock_sanitize_payload, mock_local_peripheral_check, mock_api,
                  mock_requests_resp, mock_modify, mock_save_peripheral):
        class ReqResponse(object):
            def __init__(self):
                self.status_code = 123

            def json(self):
                return {'req': 'fake response'}

        mock_sanitize_payload.return_value = None
        # if payload is of wrong type, we expect a 400
        mock_sanitize_payload.side_effect = TypeError
        self.assertEqual(AgentApi.post(self.malformed_payload)[-1], 400,
                         'Did not get the expected error when posting a malformed peripheral')
        mock_sanitize_payload.side_effect = KeyError
        self.assertEqual(AgentApi.post(self.incomplete_payload)[-1], 400,
                         'Did not get the expected error when posting an incomplete peripheral')

        mock_sanitize_payload.reset_mock(side_effect=True)
        # if peripheral is already registered locally, we also get a 400
        mock_local_peripheral_check.return_value = True
        self.assertEqual(AgentApi.post(self.valid_payload)[-1], 400,
                         'Peripheral already exists locally, but agent did not catch that')

        # otherwise, it will proceed to check if it exists in Nuvla
        mock_local_peripheral_check.return_value = False
        mock_api.return_value = FakeNuvlaApi(self.api_key,
                                             data={
                                                 'count': 1,
                                                 'resources': [
                                                     self.peripheral_content
                                                 ]
                                             })

        # but if Nuvla is not available, we expect an error
        mock_requests_resp.return_value = ReqResponse()
        mock_api.side_effect = nuvla.api.api.NuvlaError('nuvlaError', requests.Response())
        self.assertNotEqual(AgentApi.post(self.valid_payload)[-1], 200,
                            'asd')

        # if Nuvla says there's already that peripheral, then we edit
        mock_api.reset_mock(side_effect=True)
        # if edit goes wrong, we get the error code
        mock_modify.return_value = ('error msg', 500)
        self.assertEqual(AgentApi.post(self.valid_payload)[-1], 500,
                         'Peripheral edit failed, but did not get the expected error')

        # if edit goes well, then the peripheral is saved on disk and we get a 201 and the peripheral ID
        mock_modify.return_value = ({'resource-id': 'nuvlabox-peripheral/new-fake-peripheral'}, 200)
        mock_save_peripheral.return_value = None
        result_resource, result_code = AgentApi.post(self.valid_payload)
        self.assertEqual(result_code, 201,
                         'Peripheral edited but did not get the expected 201 code')
        self.assertIsInstance(result_resource, dict,
                              'Expected a resource as a response from editing the peripheral in Nuvla')
        mock_modify.assert_called()
        mock_save_peripheral.assert_called_once()

        # finally, if the peripheral does not exist in Nuvla, we need to create it
        mock_api.return_value = FakeNuvlaApi(self.api_key,
                                             data={
                                                 'count': 0,
                                                 'resource-id': self.peripheral_content['id'],
                                                 'status': 201
                                             })

        # TODO: should also test when "add" raise an exception

        # if we cannot save the peripheral on disk after the POST, then we delete it
        mock_save_peripheral.side_effect = EOFError
        self.assertEqual(AgentApi.post(self.valid_payload)[-1], 500,
                         'When failing to save peripheral locally, failed to delete it from Nuvla')
        mock_modify.assert_called_with(self.peripheral_identifier,
                                       peripheral_nuvla_id=self.peripheral_content['id'],
                                       action="DELETE")

        # if all goes well, we get the final status 201
        mock_save_peripheral.reset_mock(side_effect=True)
        self.assertEqual(AgentApi.post(self.valid_payload)[-1], 201,
                         'Returned something different than 201 even though all went well')
        mock_save_peripheral.assert_called_once()
        
        
        #NEXT - MODIFY