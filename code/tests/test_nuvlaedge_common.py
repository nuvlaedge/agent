#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import logging
from pathlib import Path
import mock
import nuvla.api
import unittest
import tests.utils.fake as fake
from agent.common import NuvlaEdgeCommon
from agent.orchestrator.docker import DockerClient


class NuvlaEdgeCommonTestCase(unittest.TestCase):

    agent_nuvlaedge_common_open = 'agent.common.NuvlaEdgeCommon.open'
    atomic_write = 'agent.common.util.atomic_write'
    get_ne_id_api = 'agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon._get_nuvlaedge_id_from_api_session'

    @mock.patch('os.path.isdir')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.set_vpn_config_extra')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.set_nuvlaedge_id')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.set_runtime_client_details')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.save_nuvla_configuration')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.set_nuvla_endpoint')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.set_installation_home')
    def setUp(self, mock_set_install_home, mock_set_nuvla_endpoint, mock_save_nuvla_conf,
              mock_set_runtime, mock_set_nuvlaedge_id, mock_set_vpn_config_extra, mock_os_isdir) -> None:
        self.ssh_pub_key = 'fakeSSHPubKey'
        os.environ['NUVLAEDGE_IMMUTABLE_SSH_PUB_KEY'] = self.ssh_pub_key
        os.environ['NUVLAEDGE_ENGINE_VERSION'] = '2.3.1'
        self.installation_home = '/home/fake'
        mock_set_install_home.return_value = self.installation_home
        mock_set_nuvla_endpoint.return_value = ('fake.nuvla.io', True)
        mock_save_nuvla_conf.return_value = True
        mock_set_runtime.return_value = DockerClient('/rootfs', self.installation_home)
        mock_os_isdir.return_value = True
        mock_set_vpn_config_extra.return_value = ''
        mock_set_nuvlaedge_id.return_value = 'nuvlabox/fake-id'
        self.obj = NuvlaEdgeCommon.NuvlaEdgeCommon()
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_init(self):
        self.assertEqual(self.obj.data_volume, "/srv/nuvlaedge/shared",
                         'Default NuvlaEdge data volume path was not set correctly')
        # confirm that SSH pub key and NBE version are set
        self.assertIsNotNone(self.obj.ssh_pub_key,
                             'SSH pub key was not taken from environment')
        self.assertIsNotNone(self.obj.nuvlaedge_engine_version,
                             'NuvlaEdge Engine version was not taken from environment')

        # by default, we should have a Docker runtime client
        self.assertIsInstance(self.obj.container_runtime, DockerClient,
                              'Container runtime not set to Docker client as expected')
        self.assertEqual(self.obj.mqtt_broker_host, 'data-gateway',
                         'data-gateway host name was not set')

        # VPN iface name should be vpn by default
        self.assertEqual(self.obj.vpn_interface_name, 'vpn',
                         'VPN interface name was not set correctly')

    def test_set_vpn_config_extra(self):
        # if previously stored, read the extra config from the file
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data='foo')):
            self.assertEqual(self.obj.set_vpn_config_extra(), 'foo',
                             'Failed to read VPN extra config from persisted file')

        # if not previously stored, read the extra config from the env, and save it into a file
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_open:
            mock_open.side_effect = [FileNotFoundError, mock.MagicMock()]
            os.environ.setdefault('VPN_CONFIG_EXTRA', r'--allow-pull-fqdn\n--client-nat snat network netmask alias')
            self.assertEqual(self.obj.set_vpn_config_extra(), '--allow-pull-fqdn\n--client-nat snat network netmask alias',
                             'Failed to read extra VPN config from environment variable')
            # TODO: fix
            # self.assertEqual(mock_open.call_count, 1,
            #                  'Failed to save extra VPN config from env into file')

    @mock.patch('os.path.exists')
    def test_set_installation_home(self, mock_exists):
        # if there is not file storing this variable, then we get it from env
        default_value = '/home/fake2'
        os.environ['HOST_HOME'] = default_value
        mock_exists.return_value = False
        self.assertEqual(self.obj.set_installation_home(''), default_value,
                         'Failed to get installation home path from env')

        # if it exists, it reads the value from the file (with strip())
        mock_exists.return_value = True
        file_value = '/home/fake3'
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data=file_value+'\n')):
            self.assertEqual(self.obj.set_installation_home('fake-file'), file_value,
                             'Unable to get installation home path from file')

    def test_set_nuvla_endpoint(self):
        # first time, will read vars from env
        os.environ['NUVLA_ENDPOINT'] = 'fake.nuvla.io'
        os.environ['NUVLA_ENDPOINT_INSECURE'] = 'True'
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_nuvla_conf:
            mock_nuvla_conf.side_effect = FileNotFoundError
            self.assertEqual(self.obj.set_nuvla_endpoint(), ('fake.nuvla.io', True),
                             'Failed to retrieve Nuvla endpoint conf from env during first run')
            # same result in case the file exists but it is malformed
            mock_nuvla_conf.side_effect = IndexError
            self.assertEqual(self.obj.set_nuvla_endpoint(), ('fake.nuvla.io', True),
                             'Failed to retrieve Nuvla endpoint conf from env when local file is malformed')

            # different variations of the Nuvla endpoint should always result on a clean endpoint string
            os.environ['NUVLA_ENDPOINT'] = 'fake.nuvla.io/'
            self.assertEqual(self.obj.set_nuvla_endpoint(), ('fake.nuvla.io', True),
                             'Failed to remove slash from endpoint string')
            os.environ['NUVLA_ENDPOINT'] = 'https://fake.nuvla.io/'
            self.assertEqual(self.obj.set_nuvla_endpoint(), ('fake.nuvla.io', True),
                             'Failed to remove https:// from endpoint string')

            # wrt being insecure, for any value different from "false" (case-insensitive) it should always be True(bool)
            os.environ['NUVLA_ENDPOINT_INSECURE'] = 'something'
            self.assertEqual(self.obj.set_nuvla_endpoint()[1], True,
                             'Failed to set Nuvla insecure to True')
            os.environ['NUVLA_ENDPOINT_INSECURE'] = 'false'
            self.assertEqual(self.obj.set_nuvla_endpoint()[1], False,
                             'Failed to set Nuvla endpoint insecure to False')

            # works with bool env vars too
            os.environ['NUVLA_ENDPOINT_INSECURE'] = '0'
            self.assertEqual(self.obj.set_nuvla_endpoint()[1], True,
                             'Failed to parse Nuvla endpoint insecure from a numerical env var')

        # but if local conf exists, read from it
        local_conf = 'NUVLA_ENDPOINT=fake.nuvla.local.io\nNUVLA_ENDPOINT_INSECURE=False'
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data=local_conf)):
            self.assertEqual(self.obj.set_nuvla_endpoint(), ('fake.nuvla.local.io', False),
                             'Unable to get Nuvla endpoint details from local file')

    @mock.patch('os.path.exists')
    def test_save_nuvla_configuration(self, mock_exists):
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_open, \
             mock.patch(self.atomic_write): # TODO: this patch is not needed but file cleanup is required
            # if file exists, don't do anything
            mock_exists.return_value = True
            self.assertIsNone(self.obj.save_nuvla_configuration('', ''),
                              'Returned something when None was expected')
            mock_open.assert_not_called()

            # if files does not exist, then write it
            mock_exists.return_value = False
            mock_open.return_value.write.return_value = None
            self.assertIsNone(self.obj.save_nuvla_configuration('file', 'content'),
                              'Returned something when None was expected')
            # TODO: fix
            # mock_open.assert_called_once_with('file', 'w')

    @mock.patch('os.path.exists')
    @mock.patch('agent.common.NuvlaEdgeCommon.DockerClient')
    @mock.patch('agent.common.NuvlaEdgeCommon.KubernetesClient')
    def test_set_runtime_client_details(self, mock_k8s, mock_docker, mock_exists):
        # if the COE is Kubernetes, get the respective client
        NuvlaEdgeCommon.ORCHESTRATOR = 'kubernetes'
        mock_k8s.return_value = 'kubernetes-class'
        self.assertEqual(self.obj.set_runtime_client_details(), 'kubernetes-class',
                         'Failed to infer underlying K8s COE and return KubernetesClient')

        # otherwise, get a DockerClient
        NuvlaEdgeCommon.ORCHESTRATOR = 'docker'
        mock_docker.return_value = 'docker-class'
        mock_exists.return_value = True
        self.assertEqual(self.obj.set_runtime_client_details(), 'docker-class',
                         'Failed to infer underlying K8s COE and return KubernetesClient')

        # unless the Docker socket does not exist
        mock_exists.return_value = False
        self.assertRaises(Exception, self.obj.set_runtime_client_details)

    @mock.patch('os.path.exists')
    def test_set_nuvlaedge_id(self, mock_exists):
        # if there's no env and not previous ID saved on file, raise exception
        mock_exists.return_value = False
        self.assertRaises(Exception, self.obj.set_nuvlaedge_id)

        # if the file exists, but is malformed, also raise exception
        mock_exists.return_value = True
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data='foo: bar')):
            self.assertRaises(Exception, self.obj.set_nuvlaedge_id)

        # if file is correct, read from it and cleanup ID
        os.environ['NUVLAEDGE_UUID'] = 'nuvlabox/fake-id'
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data='{"id": "fake-id"}')):
            self.assertEqual(self.obj.set_nuvlaedge_id(), 'nuvlabox/fake-id',
                             'Unable to correctly get NuvlaEdge ID from context file')

        # and if provided by env, compare it
        # if not equal, raise exception
        opener = mock.mock_open()

        def mocked_open(*args, **kwargs):
            return opener(*args, **kwargs)

        with mock.patch.object(Path, 'open', mocked_open):
            with mock.patch("json.load", mock.MagicMock(side_effect=[{"id": "fake-id"}])):
                os.environ['NUVLAEDGE_UUID'] = 'nuvlabox/fake-id-2'
                self.assertRaises(RuntimeError, self.obj.set_nuvlaedge_id)

        # if they are the same, all good
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data='{"id": "fake-id-2"}')):
            os.environ['NUVLAEDGE_UUID'] = 'nuvlabox/fake-id-2'
            self.assertEqual(self.obj.set_nuvlaedge_id(), 'nuvlabox/fake-id-2',
                             'Failed to check that the provided NUVLAEDGE_UUID env var is the same as the existing one')

        # if old file does not exist but env is provided, take it
        mock_exists.return_value = False
        os.environ['NUVLAEDGE_UUID'] = 'nuvlabox/fake-id-3'
        self.assertEqual(self.obj.set_nuvlaedge_id(), 'nuvlabox/fake-id-3',
                         'Unable to correctly get NuvlaEdge ID from env')

        # if the file exists and is empty but id can be found from the credential (api session)
        mock_exists.return_value = True
        del os.environ['NUVLAEDGE_UUID']
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data='')), \
                mock.patch(self.get_ne_id_api) as session_nuvlaedge_id:
            session_nuvlaedge_id.return_value = 'nuvlabox/fake-id-4'
            self.assertEqual(self.obj.set_nuvlaedge_id(), 'nuvlabox/fake-id-4',
                             'Failed to check that NuvlaEdge ID from session is used in case of an empty context file')

    def test_get_api_keys(self):
        # if there are no keys in env, return None,None
        self.assertEqual(self.obj.get_api_keys(), (None, None),
                         'Got API keys when none were defined')

        # keys are sensitive so they deleted from env if they exist
        os.environ['NUVLAEDGE_API_KEY'] = 'api-key'
        os.environ['NUVLAEDGE_API_SECRET'] = 'api-secret'
        self.assertEqual(self.obj.get_api_keys(), ('api-key', 'api-secret'),
                         'Unable to fetch API keys from env')

        for key in ['NUVLAEDGE_API_KEY', 'NUVLAEDGE_API_SECRET']:
            self.assertNotIn(key, os.environ,
                             f'{key} was not removed from env after lookup')

    def test_api(self):
        self.assertIsInstance(self.obj.api(), nuvla.api.Api,
                              'Nuvla Api instance is not of the right type')

    @mock.patch('logging.error')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.api')
    def test_push_event(self, mock_api, mock_log):
        # always get None, but if there's an error, log it
        mock_api.side_effect = TimeoutError
        mock_log.return_value = None
        self.assertIsNone(self.obj.push_event(''),
                          'Got something else than None, during an api error')

        # if all goes well, logging is not called again but still get None
        mock_api.reset_mock(side_effect=True)
        mock_api.return_value = fake.FakeNuvlaApi('')
        self.assertIsNone(self.obj.push_event('content'),
                          'Got something else than None during event push')

    def test_authenticate(self):
        api = fake.FakeNuvlaApi('')
        # the api instance should go in and out
        self.assertEqual(self.obj.authenticate(api, 'key', 'secret'), api,
                         'Unable to authenticate with Nuvla API')

    @mock.patch('agent.common.NuvlaEdgeCommon.Popen')
    def test_shell_execute(self, mock_popen):
        # execute a command as given, and return a dict with the result
        mock_popen.return_value = mock.MagicMock()
        mock_popen.return_value.communicate.return_value = ("out", "err")
        mock_popen.return_value.returncode = 0
        self.assertEqual(self.obj.shell_execute('test'),
                         {'stdout': 'out', 'stderr': 'err', 'returncode': 0},
                         'Failed to get the result of a shell command execution')

    @mock.patch('json.dumps')
    def test_write_json_to_file(self, mock_json_dumps):
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_open, \
             mock.patch(self.atomic_write) as mock_atomic_write: # TODO: this patch is not needed but file cleanup is required
            # if there's an open error, return False
            mock_open.side_effect = FileNotFoundError
            mock_atomic_write.side_effect = FileNotFoundError
            self.assertFalse(self.obj.write_json_to_file('path1', {}),
                             'Returned True when there was an error writing JSON to file')
            mock_open.reset_mock(side_effect=True)
            mock_atomic_write.reset_mock(side_effect=True)
            mock_json_dumps.side_effect = AttributeError
            self.assertFalse(self.obj.write_json_to_file('path2', {}),
                             'Returned True when there was an error with the JSON content')

        # if all goes well, return True
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_open, \
             mock.patch(self.atomic_write):
            mock_open.return_value.write.return_value = None
            mock_json_dumps.reset_mock(side_effect=True)
            self.assertTrue(self.obj.write_json_to_file('path', {}),
                            'Failed to write JSON to file')

    def test_read_json_file(self):
        # always return a dict
        file_value = '{"foo": "bar"}'
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data=file_value)):
            self.assertEqual(self.obj.read_json_file('fake-file'), json.loads(file_value),
                             'Unable to read JSON from file')

    @mock.patch.object(Path, 'exists')
    def test_get_nuvlaedge_version(self, mock_exists):
        # if the version is already an attribute of the class, just give back its major version
        major = 2
        self.obj.nuvlaedge_engine_version = f'{major}.1.0'
        self.assertEqual(self.obj.get_nuvlaedge_version(), major,
                         'Unable to infer NBE major version')

        # otherwise, get it from the data volume
        self.obj.nuvlaedge_engine_version = None
        mock_exists.return_value = True

        opener = mock.mock_open()

        def mocked_open(*args, **kwargs):
            return opener(*args, **kwargs)

        # otherwise, give back the notes as a list
        with mock.patch.object(Path, 'open', mocked_open):
            with mock.patch("json.load", mock.MagicMock(side_effect=[{'version': major}])):
                self.assertEqual(self.obj.get_nuvlaedge_version(), major,
                                 'Unable to infer NBE major version from data volume file')

        # and if no file exists either, default to latest known (2)
        mock_exists.return_value = False
        self.assertEqual(self.obj.get_nuvlaedge_version(), major,
                         'Unable to default to NBE major version')

    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.set_local_operational_status')
    def test_get_operational_status(self, mock_set_status):
        with mock.patch.object(Path, 'open') as mock_open:
            # if file not found, return UNKNOWN
            mock_open.side_effect = FileNotFoundError
            self.assertEqual(self.obj.get_operational_status(), 'UNKNOWN',
                             'Should not be able to find operational status file but still got it')
            # same for reading error, but in this case, also reset the status file
            mock_open.side_effect = IndexError
            mock_set_status.return_value = None
            self.assertEqual(self.obj.get_operational_status(), 'UNKNOWN',
                             'Should not be able to read operational status but still got it')
            mock_set_status.assert_called_once()

        # otherwise, read file and get status out of it
        file_value = 'OPERATIONAL\nsomething else\njunk'
        with mock.patch.object(Path, 'open', mock.mock_open(read_data=file_value)):
            self.assertEqual(self.obj.get_operational_status(), 'OPERATIONAL',
                             'Unable to fetch valid operational status')

    def test_get_operational_status_notes(self):
        # on any error, give back []
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_open:
            mock_open.side_effect = FileNotFoundError
            self.assertEqual(self.obj.get_operational_status_notes(), [],
                             'Got operational status notes when there should not be any')

        file_value = 'note1\nnote2\nnote3\n'

        opener = mock.mock_open(read_data=file_value)

        def mocked_open(*args, **kwargs):
            return opener(*args, **kwargs)

        # otherwise, give back the notes as a list
        with mock.patch.object(Path, 'open', mocked_open):
            self.assertEqual(self.obj.get_operational_status_notes(), file_value.splitlines(),
                             'Unable to get operational status notes')

    def test_set_local_operational_status(self):
        # should just write and return None
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_open, \
             mock.patch(self.atomic_write):
            mock_open.return_value.write.return_value = None
            self.assertIsNone(self.obj.set_local_operational_status(''),
                              'Setting the operational status should return nothing')

    def test_write_vpn_conf(self):
        with mock.patch(self.agent_nuvlaedge_common_open) as mock_open, \
             mock.patch(self.atomic_write):
            mock_open.return_value.write.return_value = None
            # if vpn fiels are not dict, it should raise a TypeError
            self.assertRaises(TypeError, self.obj.write_vpn_conf, "wrong-type")
            # if params are missing, raise KeyError
            self.assertRaises(KeyError, self.obj.write_vpn_conf, {'foo': 'bar'})
            # if all is good, return None
            vpn_values = {
                'vpn_interface_name': 'vpn',
                'vpn_ca_certificate': 'ca',
                'vpn_intermediate_ca_is': 'ca_is',
                'vpn_intermediate_ca': 'i_ca',
                'vpn_certificate': 'cert',
                'nuvlaedge_vpn_key': 'key',
                'vpn_shared_key': 's_key',
                'vpn_common_name_prefix': 'prefix',
                'vpn_endpoints_mapped': 'endpoints',
                'vpn_extra_config': 'some\nextra\nconf'
            }
            self.assertIsNone(self.obj.write_vpn_conf(vpn_values),
                              'Failed to write VPN conf')

    @mock.patch('time.sleep')
    @mock.patch.object(Path, 'exists')
    @mock.patch.object(Path, 'mkdir')
    @mock.patch('os.path.exists')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.shell_execute')
    def test_prepare_vpn_certificates(self, mock_exec, mock_os_exists, mock_mkdir, mock_exists, mock_sleep):
        # if openssl command fails, return None,None
        mock_exec.return_value = {}
        self.assertEqual(self.obj.prepare_vpn_certificates(), (None, None),
                         'Failed to exit VPN preparation when openssl fails to execute')

        # if openssl succeeds, but cred file do not exist, TimeOut and return None, None again
        mock_os_exists.return_value = False
        mock_sleep.return_value = None  # instant sleep
        mock_exec.return_value = {'returncode': 0}
        self.assertEqual(self.obj.prepare_vpn_certificates(), (None, None),
                         'Failed to raise timeout when VPN cred files are not set in time')
        mock_os_exists.assert_called()
        mock_sleep.assert_called()

        # if cred files exist, read them, and return their value
        mock_os_exists.return_value = True
        with mock.patch(self.agent_nuvlaedge_common_open, mock.mock_open(read_data='csr/key')):
            self.assertEqual(self.obj.prepare_vpn_certificates(), ('csr/key', 'csr/key'),
                             'Failed to get VPN CSR and Key values from local files')

    @mock.patch('requests.post')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.write_vpn_conf')
    @mock.patch('agent.common.NuvlaEdgeCommon.NuvlaEdgeCommon.prepare_vpn_certificates')
    def test_commission_vpn(self, mock_prep_vpn, mock_write_vpn, mock_post):
        # if VPN prep goes wrong, return false
        mock_prep_vpn.return_value = (None, None)
        self.assertFalse(self.obj.commission_vpn(),
                         'Succeeded at commissioning VPN when it should not have, cause VPN preparation was not right')

        # if prep is ok, try posting to local API
        # if post fails, return False
        mock_prep_vpn.return_value = ('csr', 'key')
        mock_post.side_effect = TimeoutError
        self.assertFalse(self.obj.commission_vpn(),
                         'Succeeded at commissioning VPN when POST request to local API failed')
        mock_post.assert_called_once()

        # if POST succeeds but returns an empty JSON, return False
        mock_post.reset_mock(side_effect=True)
        mock_post.return_value.json.return_value = {}
        self.assertFalse(self.obj.commission_vpn(),
                         'Succeeded at commissioning VPN even though POST response was an empty JSON')
        mock_post.assert_called_once()  # called once after reset

        # if POST is ok, we get VPn fields and do commissioning
        vpn_conf_fields = {
            'vpn-interface-name': 'vpn',
            'vpn-ca-certificate': 'ca',
            'vpn-intermediate-ca-is': 'ca-is',
            'vpn-intermediate-ca': 'i-ca',
            'vpn-certificate': 'cert',
            'nuvlaedge-vpn-key': 'key',
            'vpn-shared-key': 's-key',
            'vpn-common-name-prefix': 'prefix',
            'vpn-endpoints-mapped': 'endpoints'
        }
        mock_write_vpn.return_value = None
        mock_post.return_value.json.return_value = vpn_conf_fields
        self.assertTrue(self.obj.commission_vpn(),
                        'Unable to commission VPN')
