#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import agent
import json
import logging
import mock
import nuvla
import requests
import unittest
from tests.utils.fake import Fake, FakeNuvlaApi, FakeRequestsResponse
from agent.common.NuvlaBoxCommon import NuvlaBoxCommon


with mock.patch.object(agent.common.NuvlaBoxCommon, 'NuvlaBoxCommon') as mock_nb_common:
    mock_nb_common.return_value = Fake.imitate(NuvlaBoxCommon)
    from agent import AgentApi


class AgentApiTestCase(unittest.TestCase):

    agent_api_open = 'agent.AgentApi.open'

    def setUp(self):
        self.peripheral_filepath = 'mock/peripheral/path'
        self.peripheral_content = {'id': 'nuvlabox-peripheral/fake-peripheral', 'foo': 'bar'}
        AgentApi.NB.nuvlabox_id = 'nuvlabox/fake-id'
        AgentApi.NB.peripherals_dir = 'fake/path'
        AgentApi.NB.vpn_ip_file = 'fake/path/to/vpn/file'
        AgentApi.NB.vulnerabilities_file = 'fake/path/to/vpn/vuln-file'
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
        mock_requests_resp.return_value = FakeRequestsResponse()
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

    @mock.patch('os.remove')
    @mock.patch('agent.AgentApi.delete_peripheral')
    @mock.patch('agent.AgentApi.edit_peripheral')
    @mock.patch('agent.AgentApi.local_peripheral_exists')
    @mock.patch('agent.AgentApi.local_peripheral_get_identifier')
    def test_modify(self, mock_get_identifier, mock_peripheral_exists,
                    mock_edit_peripheral, mock_del_peripheral, mock_rm):
        # the accepted actions are DELETE or PUT, otherwise we expect a 405
        self.assertEqual(AgentApi.modify(self.peripheral_identifier,
                                         action='GET')[-1], 405,
                         'Peripherals API is accepting the wrong actions')

        # if there's no recognizable peripheral identifier, we should get 404
        mock_get_identifier.return_value = None
        mock_peripheral_exists.return_value = None
        self.assertEqual(AgentApi.modify(self.peripheral_identifier)[-1], 404,
                         'Peripheral ID does not exist but API tried to edit it anyway')

        # EDIT
        # - if there's a Nuvla error while editing, we shouldn't get a 200, even if the error is a 404
        mock_edit_peripheral.side_effect = nuvla.api.api.NuvlaError('nuvlaError',
                                                                    FakeRequestsResponse(status_code=404))
        self.assertNotEqual(AgentApi.modify(self.peripheral_identifier,
                                            peripheral_nuvla_id=self.peripheral_content['id'])[-1], 200,
                            'There was a Nuvla error while editing the peripheral, but still got 200')

        # - if there's any other generic error, then we should get a 500
        mock_edit_peripheral.side_effect = requests.ConnectionError
        self.assertEqual(AgentApi.modify(self.peripheral_identifier,
                                         peripheral_nuvla_id=self.peripheral_content['id'])[-1], 500,
                         'There was a generic connection error, but we did not receive the expected 500')

        # - if all goes well, we should get the the peripheral content, and a 200
        mock_edit_peripheral.reset_mock(side_effect=True)
        new_updated_peripheral = {**self.peripheral_content, **{'new-attr': 'foo'}}
        mock_edit_peripheral.return_value = FakeNuvlaApi(self.api_key,
                                                         data=new_updated_peripheral).MockResponse
        edit_output = AgentApi.modify(self.peripheral_identifier,
                                      peripheral_nuvla_id=self.peripheral_content['id'],
                                      payload=new_updated_peripheral)
        self.assertEqual(edit_output[-1], 200,
                         'Failed to edit peripheral')
        self.assertIn('new-attr', edit_output[0],
                      'The new peripheral attribute is not in the output from the edit request')

        # DELETE
        # - if Nuvla returns a 404, we should delete the local peripheral file and return 200
        mock_del_peripheral.side_effect = nuvla.api.api.NuvlaError('nuvlaError',
                                                                    FakeRequestsResponse(status_code=404))
        self.assertEqual(AgentApi.modify(self.peripheral_identifier,
                                         peripheral_nuvla_id=self.peripheral_content['id'],
                                         action='DELETE')[-1], 200,
                         'Unable to handle 404 while deleting peripheral')
        mock_rm.assert_called_once()
        # - any other Nuvla error should make this return the same error
        mock_del_peripheral.side_effect = nuvla.api.api.NuvlaError('nuvlaError',
                                                                   FakeRequestsResponse())
        self.assertNotIn(AgentApi.modify(self.peripheral_identifier,
                                         peripheral_nuvla_id=self.peripheral_content['id'],
                                         action='DELETE')[-1], [200, 404],
                         'Received unexpected status code when Nuvla generic exception occurs for peripheral deletion')
        mock_rm.assert_called_once()    # shouldn't have been called again since there was no 404
        # - for generic exceptions, the behaviour should be the same as for EDIT actions
        mock_del_peripheral.side_effect = requests.ConnectionError
        self.assertEqual(AgentApi.modify(self.peripheral_identifier,
                                         peripheral_nuvla_id=self.peripheral_content['id'],
                                         action='DELETE')[-1], 500,
                         'There was a generic connection error when deleting, but we did not receive the expected 500')

        # - finally, is all goes well, peripheral is deleted and we get a 200
        mock_del_peripheral.reset_mock(side_effect=True)
        mock_del_peripheral.return_value = FakeNuvlaApi(self.api_key,
                                                        data={'status': 200}).MockResponse
        delete_output = AgentApi.modify(self.peripheral_identifier,
                                        peripheral_nuvla_id=self.peripheral_content['id'],
                                        action='DELETE')
        self.assertEqual(delete_output[-1], 200,
                         'Failed to delete peripheral')
        self.assertIn('status', delete_output[0],
                      'Got unexpected response after deleting peripheral')

    @mock.patch('agent.AgentApi.local_peripheral_update')
    @mock.patch('agent.AgentApi.local_peripheral_exists')
    @mock.patch('agent.AgentApi.NB.api')
    def test_edit_peripheral(self, mock_api, mock_peripheral_exists, mock_peripheral_update):
        # if the peripheral file file does not exist, then we simply return the Nuvla response and don't edit the file
        mock_peripheral_exists.return_value = False
        mock_api.return_value = FakeNuvlaApi(self.api_key,
                                             data=self.peripheral_content)
        self.assertEqual(AgentApi.edit_peripheral(self.peripheral_content['id'],
                                                  self.peripheral_content,
                                                  self.peripheral_filepath).data, self.peripheral_content)
        mock_peripheral_update.assert_not_called()

        # but if the local file exists, then the return is the same, but the file is updated
        mock_peripheral_exists.return_value = True
        mock_peripheral_update.return_value = None
        self.assertEqual(AgentApi.edit_peripheral(self.peripheral_content['id'],
                                                  self.peripheral_content,
                                                  self.peripheral_filepath).data, self.peripheral_content)
        mock_peripheral_update.assert_called_once_with(self.peripheral_filepath, self.peripheral_content)

    @mock.patch('os.remove')
    @mock.patch('agent.AgentApi.local_peripheral_exists')
    @mock.patch('agent.AgentApi.NB.api')
    def test_delete_peripheral(self, mock_api, mock_peripheral_exists, mock_rm):
        # if the peripheral file file does not exist, then we simply return the Nuvla response and don't delete the file
        mock_peripheral_exists.return_value = False
        mock_api.return_value = FakeNuvlaApi(self.api_key,
                                             data=self.peripheral_content)
        self.assertEqual(AgentApi.delete_peripheral(self.peripheral_content['id'],
                                                    self.peripheral_filepath).data, self.peripheral_content)
        mock_rm.assert_not_called()

        # but if the local file exists, then the return is the same, but the file is updated
        mock_peripheral_exists.return_value = True
        mock_rm.return_value = None
        self.assertEqual(AgentApi.delete_peripheral(self.peripheral_content['id'],
                                                    self.peripheral_filepath).data, self.peripheral_content)
        mock_rm.assert_called_once_with(self.peripheral_filepath)

    @mock.patch('os.path.isdir')
    @mock.patch('glob.iglob')
    def test_find(self, mock_glob, mock_isdir):
        files = ['fake', 'path/to/fake']
        mock_glob.return_value = files
        # if none of the filenames is actually a file, then we expect an empty return
        mock_isdir.return_value = True
        self.assertEqual(AgentApi.find('param', 'value', None), ({}, 200),
                         'Returned matching peripherals when there are no files to search for')

        # if these are actually files, then we try to open them
        # but if they are not JSON formatted, we again return no matches
        mock_isdir.return_value = False
        with mock.patch(self.agent_api_open, mock.mock_open(read_data='{param: value}')):
            self.assertEqual(AgentApi.find('param', 'value', None), ({}, 200),
                             'Returned matching peripherals when there are no JSON files available')

        # if files are proper JSON, but they don't have the desired key-value inside, then there are no matches
        with mock.patch(self.agent_api_open, mock.mock_open(read_data='{"wrong-param": "wrong-value"}')):
            self.assertEqual(AgentApi.find('param', 'value', None), ({}, 200),
                             'Returned matching peripherals when none of the files have the desired key-value')

        # finally, if the files' content matches the desired key-value, a file-fileContent mapping will be returned
        desired_peripheral = {'param': 'value'}
        expected_output = {}
        list(map(lambda y: expected_output.update({y: desired_peripheral}), files))
        with mock.patch(self.agent_api_open, mock.mock_open(read_data=json.dumps(desired_peripheral))):
            self.assertEqual(AgentApi.find(list(desired_peripheral.keys())[0],
                                           list(desired_peripheral.values())[0],
                                           None),
                             (expected_output, 200),
                             'Failed to return matching peripherals')

    @mock.patch('agent.AgentApi.local_peripheral_exists')
    def test_get(self, mock_peripheral_exists):
        # if peripherals does not exist locally, then return 404
        mock_peripheral_exists.return_value = False
        self.assertEqual(AgentApi.get(self.peripheral_identifier)[-1], 404,
                         'Did not return 404 for a peripheral that does not exist')

        mock_peripheral_exists.return_value = True
        # if it exists but its file content is malformed, return a 500
        with mock.patch(self.agent_api_open, mock.mock_open(read_data='bad-json')):
            self.assertEqual(AgentApi.get(self.peripheral_identifier)[-1], 500,
                             'Not returning 500 when peripheral file is malformed')

        # finally, if all is good, it returns the peripheral file content (JSON) and a 200
        with mock.patch(self.agent_api_open, mock.mock_open(read_data=json.dumps(self.peripheral_content))):
            self.assertEqual(AgentApi.get(self.peripheral_identifier), (self.peripheral_content, 200),
                             'Failed to find and return existing local peripheral')

    @mock.patch(agent_api_open)
    def test_save_vpn_ip(self, mock_open):
        # if the path does not exist, throw an exception
        mock_open.side_effect = FileNotFoundError
        self.assertRaises(FileNotFoundError, AgentApi.save_vpn_ip, '1.1.1.1')

        # otherwise, it writes the file and returns nothing
        mock_open.reset_mock(side_effect=True)
        with mock.patch(self.agent_api_open, mock.mock_open(), create=True):
            self.assertIs(AgentApi.save_vpn_ip('1.1.1.1'), None,
                          'Failed to write VPN IP into file')

    @mock.patch(agent_api_open)
    def test_save_vulnerabilities(self, mock_open):
        # if the path does not exist, throw an exception
        mock_open.side_effect = FileNotFoundError
        self.assertRaises(FileNotFoundError, AgentApi.save_vulnerabilities, {})

        # otherwise, it writes the file and returns nothing
        mock_open.reset_mock(side_effect=True)
        with mock.patch(self.agent_api_open, mock.mock_open(), create=True):
            self.assertIs(AgentApi.save_vulnerabilities({}), None,
                          'Failed to write vulnerabilities into file')
