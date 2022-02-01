#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import datetime
import json
import subprocess
import docker
import logging
import mock
import requests
import unittest
import tests.utils.fake as fake
import yaml
import agent.common.NuvlaBoxCommon as NuvlaBoxCommon


class ContainerRuntimeDockerTestCase(unittest.TestCase):

    agent_nuvlabox_common_open = 'agent.common.NuvlaBoxCommon.open'

    def setUp(self) -> None:
        self.hostfs = '/fake-rootfs'
        self.host_home = '/home/fakeUser'
        self.obj = NuvlaBoxCommon.DockerClient(self.hostfs, self.host_home)
        self.local_docker_client = docker.from_env()
        self.fake_swarm_tokens = {
            'JoinTokens': {
                'Manager': 'token-manager',
                'Worker': 'token-worker'
            }
        }
        self.job_engine_lite_component = 'fake-job-lite'
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        self.obj.client.close()
        self.local_docker_client.close()
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

    def test_get_node_info(self):
        self.assertIn('ID', self.obj.get_node_info(),
                      'Unable to retrieve Docker info')

        self.assertIsInstance(self.obj.get_node_info(), dict,
                              'Docker info should be returned as a dict')

        self.assertEqual(self.obj.get_node_info().keys(), self.local_docker_client.info().keys(),
                         'Get node info return a different value than the real Docker info')

    def test_get_host_os(self):
        self.assertIsInstance(self.obj.get_host_os(), str,
                              'Host OS should be a string')

    @mock.patch('docker.api.swarm.SwarmApiMixin.inspect_swarm')
    def test_get_join_tokens(self, mock_docker):
        # if there are no tokens (Swarm is off), we should get an empty tuple
        mock_docker.return_value = {}
        self.assertEqual(self.obj.get_join_tokens(), (),
                         'Returned Swarm tokens even though Swarm is NOT enabled')

        # otherwise, the tokens should be received
        mock_docker.return_value = self.fake_swarm_tokens
        self.assertEqual(self.obj.get_join_tokens(),
                         (self.fake_swarm_tokens['JoinTokens']['Manager'],
                          self.fake_swarm_tokens['JoinTokens']['Worker']),
                         'Did not get the expected Swarm tokens')

        # is there's a Docker error, we should get an empty tuple
        mock_docker.side_effect = docker.errors.APIError("fake", response=requests.Response())
        self.assertEqual(self.obj.get_join_tokens(), (),
                         'Returned Swarm tokens even though Docker threw an exception')

    @mock.patch('docker.models.nodes.NodeCollection.list')
    def test_list_nodes(self, mock_docker):
        # a filter should be accepted as an arg
        fake_filter = {'test': 'foo'}
        mock_docker.return_value = []
        self.assertEqual(self.obj.list_nodes(optional_filter=fake_filter), [],
                         'Listing Docker nodes when there are none')
        mock_docker.assert_called_once_with(filters=fake_filter)

        # make sure the returned list is consistent with what's provided by Docker
        mock_docker.return_value = [1, 2, 3]
        self.assertEqual(len(self.obj.list_nodes()), 3,
                         'Number of Docker nodes does not match with true value')

        # and when Docker throws an error, this shall too
        mock_docker.side_effect = docker.errors.APIError("", response=requests.Response())
        self.assertRaises(docker.errors.APIError, self.obj.list_nodes)

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.list_nodes')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_cluster_info(self, mock_get_node_info, mock_list_nodes):
        # if Swarm is not enabled, we should get an empty dict
        mock_get_node_info.return_value = {'Swarm': {}}
        self.assertEqual(self.obj.get_cluster_info(), {},
                         'Returned cluster info when there is no cluster')

        # if not a Swarm manager, then again {} is returned
        mock_get_node_info.return_value = {'Swarm': {'ControlAvailable': ''}}
        self.assertEqual(self.obj.get_cluster_info(), {},
                         'Returned cluster info when node is not a manager')

        # if nodes exist...

        mock_get_node_info.return_value = {
            'Swarm': {
                'ControlAvailable': True
            },
            'Cluster': {
                'ID': 'fake-id'
            }
        }

        # if all nodes are ready, we get them all back
        mock_list_nodes.return_value = [fake.MockDockerNode(), fake.MockDockerNode()]
        self.assertIn('cluster-id', self.obj.get_cluster_info(),
                      'Expecting cluster-id in cluster info')
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-managers']), 2,
                         'Expecting 2 cluster nodes, but got something else')
        self.assertEqual(len(self.obj.get_cluster_info().keys()), 4,
                         'Expecting 4 keys to define cluster, but got something else')

        # if not all nodes are ready, then we just get the ones which are ready
        mock_list_nodes.return_value = [fake.MockDockerNode(), fake.MockDockerNode(state='not-ready')]
        self.assertIn('cluster-orchestrator', self.obj.get_cluster_info(),
                      'Expecting cluster-orchestrator in cluster info')
        self.assertIn(self.obj.get_cluster_info()['cluster-orchestrator'].lower(), ['docker', 'swarm'],
                      'Expecting Docker-based COE but got a different orchestrator')
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-workers']), 1,
                         'Expecting 1 worker in cluster info, but got something else')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_api_ip_port(self, mock_get_nodes_info):
        # if Swarm info has an address, we should just get that back with port 5000
        node_addr = '1.2.3.4'
        mock_get_nodes_info.return_value = {
            'Swarm': {
                'NodeAddr': node_addr
            }
        }

        self.assertEqual(self.obj.get_api_ip_port(), (node_addr, 5000),
                         'Expected default Swarm NodeAddr with port 5000, but got something else instead')

        # otherwise, we try to read the machine IP from the disk
        mock_get_nodes_info.return_value = {'Swarm': {}}
        # if there's a valid IP in this file, we return it
        tcp_file = '''sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   6: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 51149 1 ffffffc1c9be2e80 100 0 0 10 0
   7: 0100007F:13D8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 58062 1 ffffffc1dea25d00 100 0 0 10 0
   8: 2D28A8C0:0016 652AA8C0:D6C9 01 00000024:00000000 01:00000015 00000000     0        0 3610139 4 ffffffc10cd3f440 22 4 29 10 -1
   9: 0100007F:ECA0 0100007F:13D8 06 00000000:00000000 03:00000577 00000000     0        0 0 3 ffffffc0d1887ef0
   '''
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data=tcp_file)):
            self.assertEqual(self.obj.get_api_ip_port(), ('192.168.40.45', 5000),
                             'Could not get valid IP from filesystem')

        # if there's no valid IP in this file, then we return 127.0.0.1
        tcp_file = '''sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0B83 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22975 1 ffffffc1dea20000 100 0 0 10 0
   1: 00000000:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 46922 1 ffffffc1c9be1740 100 0 0 10 0
   '''
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data=tcp_file)):
            self.assertEqual(self.obj.get_api_ip_port(), ('127.0.0.1', 5000),
                             'Could not get default IP from filesystem')

    @mock.patch('docker.models.containers.ContainerCollection.get')
    def test_has_pull_job_capability(self, mock_containers_get):
        # if the job-lite does not exist, we get False
        mock_containers_get.side_effect = docker.errors.NotFound
        self.assertFalse(self.obj.has_pull_job_capability(),
                         'Job lite can not be found but returned True anyway')

        # same for any other exception
        mock_containers_get.side_effect = EOFError
        self.assertFalse(self.obj.has_pull_job_capability(),
                         'Error occurred but returned True anyway')

        # otherwise, we infer its Docker image
        mock_containers_get.reset_mock(side_effect=True)

        mock_containers_get.return_value = fake.MockContainer(status='running')

        # if the container is running, we return false
        self.assertFalse(self.obj.has_pull_job_capability(),
                         'Returned True even when job-lite container is not paused')

        # the container is supposed to be paused
        mock_containers_get.return_value = fake.MockContainer()
        self.assertTrue(self.obj.has_pull_job_capability(),
                        'Should have found the job-lite component, but has not')
        self.assertEqual(self.obj.job_engine_lite_image, 'fake-image',
                         'Set the wrong job-lite Docker image')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.cast_dict_to_list')
    @mock.patch('docker.api.swarm.SwarmApiMixin.inspect_node')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_node_labels(self, mock_get_node_info, mock_inspect_node, mock_cast_dict_to_list):
        # errors while inspecting node should cause it to return empty list
        mock_inspect_node.side_effect = KeyError
        node = {
            'Swarm': {
                'NodeID': 'fake-id'
            }
        }
        mock_get_node_info.return_value = node
        err = 'Exception not caught while getting node labels'
        self.assertEqual(self.obj.get_node_labels(), [],
                         err)

        mock_inspect_node.reset_mock(side_effect=True)
        mock_get_node_info.side_effect = docker.errors.NullResource
        self.assertEqual(self.obj.get_node_labels(), [],
                         err)

        mock_get_node_info.reset_mock(side_effect=True)
        labels = [1, 2]
        mock_inspect_node.return_value = {
            'Spec': {
                'Labels': labels
            }
        }
        mock_cast_dict_to_list.return_value = labels
        self.assertEqual(self.obj.get_node_labels(), labels,
                         'Unable to get node labels')
        mock_cast_dict_to_list.assert_called_once_with(labels)

    @mock.patch('docker.models.containers.ContainerCollection.get')
    def test_is_vpn_client_running(self, mock_containers_get):
        mock_containers_get.return_value = fake.MockContainer(status='running')
        # if vpn is running, returns True
        self.assertTrue(self.obj.is_vpn_client_running(),
                        'Says vpn-client is not running when it is')

        # False otherwise
        mock_containers_get.return_value = fake.MockContainer(status='paused')
        self.assertFalse(self.obj.is_vpn_client_running(),
                         'Says vpn-client is running, but it is not')

    @mock.patch('docker.models.containers.ContainerCollection.run')
    def test_install_ssh_key(self, mock_docker_run):
        # if all goes well, we expect True
        mock_docker_run.return_value = None
        self.assertTrue(self.obj.install_ssh_key('fake-pub-key', 'fake-ssh-folder'),
                        'Unable to install SSH key')

        # if an exception is thrown, it should be raised and we get no return
        mock_docker_run.side_effect = Exception
        self.assertRaises(Exception, self.obj.install_ssh_key, 'fake-pub-key', 'fake-ssh-folder',
                          'Exception was not thrown when failing to install SSH key')

    @mock.patch('docker.models.containers.ContainerCollection.get')
    def test_is_nuvla_job_running(self, mock_containers_get):
        job_id = 'fake-id'
        job_exec_id = 'fake-exec-id'
        # if docker cannot find the job container, then return False
        mock_containers_get.side_effect = docker.errors.NotFound('', requests.Response())
        self.assertFalse(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                         'Says job execution container exists when it should not')

        # any other exception means we can't assess this, so returns True by default
        mock_containers_get.side_effect = TimeoutError
        self.assertTrue(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                        'Cannot know if job execution container is running, but says it is not running')

        mock_containers_get.reset_mock(side_effect=True)
        # if container is found, but the container object is defective, assume it is True
        mock_containers_get.return_value = fake.MockContainer(status='fake-status')
        mock_containers_get.return_value.kill = mock.Mock()
        mock_containers_get.return_value.kill.side_effect = AttributeError
        # throw AttributeError
        self.assertTrue(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                        'Says job execution container is not running when it actually does not know if it is')

        mock_containers_get.return_value = fake.MockContainer(status='created')
        mock_containers_get.return_value.remove = mock.Mock()
        mock_containers_get.return_value.remove.side_effect = docker.errors.NotFound('', requests.Response())
        # throw docker.errors.NotFound
        self.assertTrue(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                        'Says job execution container is running when actually it does not even exist')

        # and running, return True
        mock_containers_get.return_value = fake.MockContainer(status='running')
        self.assertTrue(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                        'Says job execution container is not running when it is not')
        # same for status=restarting
        mock_containers_get.return_value = fake.MockContainer(status='restarting')
        self.assertTrue(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                        'Says job execution container is not running but it is restarting')

        # finally, if status is either created or not known, container is killed and this returns False
        mock_containers_get.return_value = fake.MockContainer(status='created')
        self.assertFalse(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                         'Failed to remove created job execution container')
        mock_containers_get.return_value = fake.MockContainer(status='non-a-status')
        self.assertFalse(self.obj.is_nuvla_job_running(job_id, job_exec_id),
                         'Failed to kill job execution container in unknown state')

    @mock.patch('docker.api.network.NetworkApiMixin.connect_container_to_network')
    @mock.patch('docker.models.containers.ContainerCollection.run')
    @mock.patch('docker.models.containers.ContainerCollection.get')
    def test_launch_job(self, mock_containers_get, mock_containers_run, mock_net_connect):
        job_id = 'fake-id'
        job_exec_id = 'fake-exec-id'
        nuvla = 'https://fake-nuvla.io'

        # if there's an error while getting the compute-api, we expect None
        mock_containers_get.side_effect = TimeoutError
        self.assertIs(self.obj.launch_job(job_id, job_exec_id, nuvla), None,
                      'compute-api could not be found, but still got something else than None')
        mock_containers_run.assert_not_called()

        # otherwise we try to launch the job execution container
        mock_containers_get.reset_mock(side_effect=True)
        mock_containers_get.return_value = fake.MockContainer()
        mock_containers_run.return_value = None
        self.assertIs(self.obj.launch_job(job_id, job_exec_id, nuvla), None,
                      'Unable to launch job execution container')
        mock_containers_run.assert_called_once()
        mock_net_connect.assert_called_once_with(job_exec_id, 'bridge')

    def test_collect_container_metrics_cpu(self):
        cpu_stat = {
            "cpu_stats": {
                "cpu_usage": {
                    "total_usage": "10"
                },
                "system_cpu_usage": "100",
                "online_cpus": 2
            },
        }
        old_cpu_total = 5
        old_cpu_system = 50
        err = []
        # if all is well, we should expect a float value bigger than 0
        self.assertIsInstance(self.obj.collect_container_metrics_cpu(cpu_stat, old_cpu_total, old_cpu_system, err),
                              float,
                              "Received unexpected type of CPU usage percentage for container")
        self.assertEqual(self.obj.collect_container_metrics_cpu(cpu_stat, old_cpu_total, old_cpu_system, err), 20.0,
                         "The provided default should return a CPU usage of 20%, but that was not the case")
        self.assertEqual(len(err), 0,
                         "There should not have been any CPU collection errors")

        # if online_cpus is not reported, then we get 0% usage
        cpu_stat['cpu_stats'].pop('online_cpus')
        self.assertEqual(self.obj.collect_container_metrics_cpu(cpu_stat, old_cpu_total, old_cpu_system, err), 0.0,
                         "Expecting 0% CPU usage due to lack of details, but got something else")

        # if a mandatory attribute does not exist, then we get 0% again, but with an error
        cpu_stat.pop('cpu_stats')
        self.assertEqual(self.obj.collect_container_metrics_cpu(cpu_stat, old_cpu_total, old_cpu_system, err), 0.0,
                         "Expecting 0% CPU usage due to missing mandatory keys, but got something else")
        self.assertGreater(len(err), 0,
                           "Expecting an error due to the lack to CPU info to collect, but did not get any")

    def test_collect_container_metrics_mem(self):
        mem_stat = {
            "memory_stats": {
                "usage": 1024*1024,
                "limit": 2*1024*1024
            }
        }
        err = []
        # if all is well, we expect a float value higher than 0.0%
        self.assertEqual(self.obj.collect_container_metrics_mem(mem_stat, err), (50.0, 1, 2),
                         "Expecting a memory usage of 50%, but got something else instead")
        self.assertEqual(len(err), 0,
                         "There should not have been any Memory collection errors")

        # if the memory limit is set to 0, then we expect 0%, with no errors
        mem_stat['memory_stats']['limit'] = 0
        self.assertEqual(self.obj.collect_container_metrics_mem(mem_stat, err), (0.0, 1, 0),
                         "Expecting a memory usage of 50%, but got something else instead")
        self.assertEqual(len(err), 0,
                         "There should not have been any Memory collection errors, even though the results was 0%")

        # if there are missing fields, then an error should be added, and 0% should be returned
        mem_stat.pop('memory_stats')
        self.assertEqual(self.obj.collect_container_metrics_mem(mem_stat, err), (0.0, 0.0, 0.0),
                         "Expecting 0% due to missing fields, but got something else")
        self.assertGreater(len(err), 0,
                           "There should have been Memory collection errors since fields are missing")

    def test_collect_container_metrics_net(self):
        net_stat = {
            "networks": {
                "iface1": {
                    "rx_bytes": 1*1000*1000,
                    "tx_bytes": 1*1000*1000
                },
                "iface2": {
                    "rx_bytes": 1*1000*1000,
                    "tx_bytes": 1*1000*1000
                }
            }
        }
        # if all goes well, we expect 2MB received and 2MB sent
        self.assertEqual(self.obj.collect_container_metrics_net(net_stat), (2, 2),
                         'Failed to sum network counters')

    def test_collect_container_metrics_block(self):
        blk_stat = {
            "blkio_stats": {
                "io_service_bytes_recursive": [
                    {
                        "value": 1*1000*1000
                    },
                    {
                        "value": 2*1000*1000
                    }]
            }
        }
        err = []
        # if all goes well, we expect 1MB blk_in and 2MB blk_out, and no errors
        self.assertEqual(self.obj.collect_container_metrics_block(blk_stat, err), (2, 1),
                         'Failed to get block statistics for a container')
        self.assertEqual(err, [],
                         'Reporting errors on blk stats when there should not be any')

        # if the blk_stats are misformatted or there is any other exception during collection,
        # then we get 0MBs for the corresponding metric, and an error
        blk_stat['blkio_stats']['io_service_bytes_recursive'][0]['value'] = "saasd" # not a number
        self.assertEqual(self.obj.collect_container_metrics_block(blk_stat, err), (2, 0),
                         'Expected 0MBs for blk_in (due to misformatted value, but got something else instead')
        self.assertEqual(err, ['blk_in'],
                         'An error occurred while collecting the container blk_in, but it was not reported')

        # if blkio stats are missing a field, then we expect (0,0) MBs
        blk_stat.pop('blkio_stats')
        err = []
        self.assertEqual(self.obj.collect_container_metrics_block(blk_stat, err), (0, 0),
                         'Expected 0MBs for container block stats (due to missing stats), but got something else')
        self.assertEqual(err, [],
                         'There should be no errors reported when blk stats are not given by Docker')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.collect_container_metrics_block')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.collect_container_metrics_net')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.collect_container_metrics_mem')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.collect_container_metrics_cpu')
    @mock.patch('docker.api.container.ContainerApiMixin.stats')
    @mock.patch('docker.models.containers.ContainerCollection.list')
    def test_collect_container_metrics(self, mock_containers_list, mock_container_stats, mock_get_cpu,
                                       mock_get_mem, mock_get_net, mock_get_block):
        # if there are no containers, we should get an empty list
        mock_containers_list.return_value = []
        stats = []
        mock_container_stats.return_value = iter(stats)
        self.assertEqual(self.obj.collect_container_metrics(), [],
                         'Get container stats when there are no containers running')

        # otherwise...
        mock_containers_list.return_value = [fake.MockContainer()]
        mock_get_mem.return_value = (1, 2 ,3)
        mock_get_cpu.return_value = 50
        mock_get_net.return_value = (1, 2)
        mock_get_block.return_value = (1, 2)
        # if one container has malformed CPU stats, the "old_cpu" variable should be set to (0,0) when collecting CPU
        old_cpu_total_usage = 1
        old_cpu_system_cpu_usage = 1
        cpu_stats = {
            "cpu_usage": {
                "total_usage": old_cpu_total_usage
            },
            "system_cpu_usage": old_cpu_system_cpu_usage,
            "online_cpus": 2
        }
        stats = [
            '{"cpu_stats": {}}',
            '{"cpu_stats": %s}' % json.dumps(cpu_stats)
        ]
        mock_container_stats.return_value = iter(stats)
        self.assertIsInstance(self.obj.collect_container_metrics(), list,
                              'Expecting a list from the container metrics collection, but got something else')
        # there is only 1 container, so each collector should only have been called once
        mock_get_cpu.assert_called_once_with(json.loads(stats[1]), 0, 0, [])

        # if all containers have valid stats though, we should expect the "old_cpu" to be different from (0,0)
        # and the output to container all the expected fields to be included in the telemetry
        mock_get_cpu.reset_mock()
        stats[0] = stats[1]
        mock_container_stats.return_value = iter(stats)
        expected_fields = ['id', 'name', 'container-status',
                           'cpu-percent', 'mem-usage-limit', 'mem-percent',
                           'net-in-out', 'blk-in-out', 'restart-count']
        self.assertTrue(set(expected_fields).issubset(list(self.obj.collect_container_metrics()[0].keys())),
                        'Received malformed container stats from the statistics collection mechanism')
        mock_get_cpu.assert_called_once_with(json.loads(stats[1]), old_cpu_total_usage, old_cpu_system_cpu_usage, [])

    @mock.patch('agent.common.NuvlaBoxCommon.socket.gethostname')
    @mock.patch('docker.models.containers.ContainerCollection.get')
    @mock.patch('docker.models.containers.ContainerCollection.list')
    def test_get_installation_parameters(self, mock_containers_list, mock_containers_get, mock_gethostname):
        search_label = 'fake-label'
        agent_id = 'my-fake-id'
        # if the agent container cannot find itself, it raises an exception
        mock_containers_list.return_value = [fake.MockContainer(myid=agent_id), fake.MockContainer()]
        mock_gethostname.return_value = 'fake-hostname'
        mock_containers_get.side_effect = docker.errors.NotFound('', requests.Response())
        self.assertRaises(docker.errors.NotFound, self.obj.get_installation_parameters, search_label)

        # otherwise...
        mock_containers_get.reset_mock(side_effect=True)
        mock_containers_get.return_value = fake.MockContainer(myid=agent_id)
        # since all labels exist, the output should container the respective fields for the telemetry
        expected_fields = ['project-name', 'working-dir', 'config-files', 'environment']
        self.assertIsInstance(self.obj.get_installation_parameters(search_label), dict,
                              'Expecting installation parameters to be a JSON structure')
        self.assertTrue(set(expected_fields).issubset(self.obj.get_installation_parameters(search_label)),
                        f'Installation parameters are missing the required telemetry fields: {expected_fields}')

        # if containers have labels that are supposed to be ignored, these should not be in the returned value
        new_agent_container = fake.MockContainer(myid=agent_id)
        ignore_env = f'{self.obj.ignore_env_variables[0]}=some-fake-env-value-to-ignore'
        new_agent_container.attrs['Config']['Env'] = [ignore_env]
        mock_containers_list.return_value = [fake.MockContainer(), new_agent_container]
        mock_containers_get.return_value = new_agent_container
        self.assertNotIn(ignore_env,
                         self.obj.get_installation_parameters(search_label)['environment'],
                         'Unwanted environment variables are not being properly ignored')

        # other environment variables will be included though
        include_env = 'some-env=some-fake-env-value-NOT-to-ignore'
        new_agent_container.attrs['Config']['Env'].append(include_env)
        mock_containers_list.return_value = [fake.MockContainer(), new_agent_container]
        mock_containers_get.return_value = new_agent_container
        self.assertIn(include_env,
                      self.obj.get_installation_parameters(search_label)['environment'],
                      'Expected environment variables are not in the final parameters')

        # and also make sure the config-files are not duplicated, even if there are many containers reporting
        # the same filenames
        mock_containers_list.return_value = [fake.MockContainer(), new_agent_container, fake.MockContainer()]
        self.assertEqual(sorted(self.obj.get_installation_parameters(search_label)['config-files']),
                         sorted(new_agent_container.labels['com.docker.compose.project.config_files'].split(',')),
                         'Installation config files are not reported correctly')

        # we only take the config-files from the last updated container
        updated_container = fake.MockContainer()
        updated_container.attrs['Created'] = datetime.datetime.utcnow().isoformat()
        updated_container.labels['com.docker.compose.project.config_files'] = 'c.yml'
        mock_containers_list.return_value = [new_agent_container, updated_container]
        self.assertEqual(sorted(self.obj.get_installation_parameters(search_label)['config-files']),
                         ['c.yml'],
                         'Installation config files are not reported correctly after an update')

        # finally, if one of the compose file labels are missing from the agent_container, we get None
        new_agent_container.labels['com.docker.compose.project'] = None
        mock_containers_get.return_value = new_agent_container
        self.assertIsNone(self.obj.get_installation_parameters(search_label),
                          'Expected no installation parameters due to missing Docker Compose labels, but got something')

    def test_read_system_issues(self):
        node_info = {
            'Swarm': {
                'Error': 'some-fake-error'
            },
            'Warnings': ['fake-warn-1', 'fake-warn-2']
        }
        # if all is good, we should get 1 error and 2 warnings
        self.assertEqual(self.obj.read_system_issues(node_info), ([node_info['Swarm']['Error']], node_info['Warnings']),
                         'Got unexpected system errors/warnings')

        # and if there are no errors nor warnings, we should get two empty lists
        self.assertEqual(self.obj.read_system_issues({}), ([], []),
                         'Expected no errors nor warnings, but got something instead')

    def test_get_node_id(self):
        node_info = {
            'Swarm': {
                'NodeID': 'some-fake-id'
            }
        }
        # should always return the ID value indicated in the passed argument
        self.assertEqual(self.obj.get_node_id(node_info), node_info['Swarm']['NodeID'],
                         'Returned NodeID does not match the real one')

    def test_get_cluster_id(self):
        node_info = {
            'Swarm': {
                'Cluster': {
                    'ID': 'some-fake-cluster-id'
                }
            }
        }
        # should always return the ID value indicated in the passed argument
        # and ignore the named argument
        self.assertEqual(self.obj.get_cluster_id(node_info, default_cluster_name='some-name'),
                         node_info['Swarm']['Cluster']['ID'],
                         'Returned Cluster ID does not match the real one')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_cluster_managers(self, mock_get_node):
        node_info = {
            'Swarm': {
                'RemoteManagers': [{'NodeID': 'manager-1'}, {'NodeID': 'manager-2'}]
            }
        }
        mock_get_node.return_value = node_info
        # if all is good, we should get the managers IDs
        self.assertEqual(self.obj.get_cluster_managers(),
                         list(map(lambda x: x['NodeID'], node_info['Swarm']['RemoteManagers'])),
                         'Did not get the expected cluster managers IDs')

        # but if there are none, we get an empty list
        mock_get_node.return_value = {}
        self.assertEqual(self.obj.get_cluster_managers(), [],
                         'Did not get the expected cluster managers IDs')

    def test_get_host_architecture(self):
        node_info = {
            'Architecture': 'fake-arch'
        }
        # simple attribute lookup
        self.assertEqual(self.obj.get_host_architecture(node_info), node_info['Architecture'],
                         'Host architecture does not match the real one')

    def test_get_hostname(self):
        node_info = {
            'Name': 'fake-name'
        }
        # simple attribute lookup
        self.assertEqual(self.obj.get_hostname(node_info), node_info['Name'],
                         'Hostname does not match the real one')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_cluster_join_address(self, mock_get_node):
        node_id = 'fake-node-id'
        node_info = {
            'Swarm': {
                'RemoteManagers': [{'NodeID': node_id, 'Addr': 'good-addr'},
                                   {'NodeID': 'manager-2', 'Addr': 'bad-addr'}]
            }
        }
        # if this node's ID is in the managers list, return its addr
        mock_get_node.return_value = node_info
        self.assertEqual(self.obj.get_cluster_join_address(node_id), node_info['Swarm']['RemoteManagers'][0]['Addr'],
                         'Unable to report the right cluster manager address')

        # if the Addr attribute is not set, then we should get None
        node_info['Swarm']['RemoteManagers'][0].pop('Addr')
        mock_get_node.return_value = node_info
        self.assertIsNone(self.obj.get_cluster_join_address(node_id),
                          'Returned a join address where there should not be one')

        # same result if this node ID is not in the list of managers
        self.assertIsNone(self.obj.get_cluster_join_address('some-other-fake-node-id'),
                          'Returned a join address when this node is not a manager')

    def test_is_node_active(self):
        node = fake.MockDockerNode()
        # if node is ready, should return its ID (in this case a random number)
        self.assertIsNotNone(self.obj.is_node_active(node),
                             'Saying node is not active when it is')

        # otherwise, always returns None
        node = fake.MockDockerNode(state='pending')
        self.assertIsNone(self.obj.is_node_active(node),
                          'Saying node is active when it is not')

    @mock.patch('docker.models.plugins.PluginCollection.list')
    def test_get_container_plugins(self, mock_plugins):
        plugin_obj = mock.MagicMock()
        plugin_obj.enabled = True
        plugin_obj.name = 'docker.plugin.fake'

        mock_plugins.return_value = [plugin_obj, plugin_obj]
        # if there are enabled plugins, we expect a list with their names
        self.assertEqual(self.obj.get_container_plugins(), ['docker.plugin.fake', 'docker.plugin.fake'],
                         'Unable to retrieve container plugins')

        # if there are no plugins, we get an empty list
        mock_plugins.return_value = []
        self.assertEqual(self.obj.get_container_plugins(), [],
                         'Returned container plugins when there are none')

        # same for plugins that are not active
        plugin_obj.enabled = False
        mock_plugins.return_value = [plugin_obj, plugin_obj]
        self.assertEqual(self.obj.get_container_plugins(), [],
                         'Returned container plugins when none are active')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.infer_if_additional_coe_exists')
    def test_define_nuvla_infra_service(self, mock_infer_extra_coe):
        mock_infer_extra_coe.return_value = {}
        # if the api_endpoint is not set, the infra is not set either
        self.assertEqual(self.obj.define_nuvla_infra_service('', []), {},
                         'Returned a valid infra service when there is no API endpoint')

        # otherwise, destructs the TLS keys and gives back the commissioning payload for the IS
        is_keys = ["swarm-client-ca", "swarm-client-cert", "swarm-client-key", "swarm-endpoint"]
        self.assertTrue(set(is_keys).issubset(self.obj.define_nuvla_infra_service('valid-api-endpoint',
                                                                                  ['ca', 'cert', 'key'])),
                        'Failed to setup Swarm infrastructure service payload for commissioning')

        # if there are no TLS keys, they are not included in the IS payload
        mock_infer_extra_coe.return_value = {}
        self.assertEqual(self.obj.define_nuvla_infra_service('valid-api-endpoint', []),
                         {'swarm-endpoint': 'valid-api-endpoint'},
                         'Returned more IS keys than just the expected API endpoint')

        # the result should not be affected by the inference of the extra COE throwing an exeception
        mock_infer_extra_coe.side_effect = ConnectionError
        self.assertEqual(self.obj.define_nuvla_infra_service('valid-api-endpoint', []),
                         {'swarm-endpoint': 'valid-api-endpoint'},
                         'Infra service definition was affected by k8s discovery function exception')

        # and if there's an extra k8s infra, it should be appended to the final infra
        mock_infer_extra_coe.reset_mock(side_effect=True)
        mock_infer_extra_coe.return_value = {'k8s-stuff': True}
        self.assertIn('k8s-stuff', self.obj.define_nuvla_infra_service('valid-api-endpoint', ['ca', 'cert', 'key']),
                      'Additional COE was not added to infrastructure service payload')
        self.assertEqual(len(self.obj.define_nuvla_infra_service('valid-api-endpoint', ['ca', 'cert', 'key']).keys()),
                         5,
                         'Unexpected number of infrastructure service fields')

    def test_get_partial_decommission_attributes(self):
        # returns a constant, so let's just make sure that all return list items start with 'swarm'
        self.assertTrue(all(x.startswith('swarm') for x in self.obj.get_partial_decommission_attributes()),
                        'Received partial decommissioning attributes that are not Swarm related')

    @mock.patch('yaml.safe_load')
    @mock.patch('os.path.isfile')
    def test_is_k3s_running(self, mock_isfile, mock_yaml):
        # if k3s_addr is not set, we get {}
        self.assertEqual(self.obj.is_k3s_running(''), {},
                         'Received k3s details even though no address was provided')

        # same if the k3s config file cannot be found
        mock_isfile.return_value = False
        self.assertEqual(self.obj.is_k3s_running('1.1.1.1'), {},
                         'Received k3s details even though k3s config file does not exist')

        mock_isfile.return_value = True
        # same again if the k3s config is malformed
        mock_yaml.side_effect = yaml.YAMLError
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data='{"notyaml": True}')):
            self.assertEqual(self.obj.is_k3s_running('1.1.1.1'), {},
                             'Received k3s details even though the k3s config file is malformed')

        mock_yaml.reset_mock(side_effect=True)
        ca = b'ca'
        cert = b'cert'
        key = b'key'
        kubeconfig = {
            'clusters': [
                {
                    'cluster': {
                        'server': 'https://fake-server:6443',
                        'certificate-authority-data': base64.b64encode(ca),
                    }
                }
            ]
        }
        mock_yaml.return_value = kubeconfig

        # if k3s config can be read, but there's an exception while retrieving the values from it, we again get {}
        # let's force a KeyError by omitting the users from the k3s config
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data='{"notyaml": True}')):
            self.assertEqual(self.obj.is_k3s_running('1.1.1.1'), {},
                             'Received k3s details even though the k3s config cannot be parsed')

        kubeconfig['users'] = [
            {
                'user': {
                    'client-certificate-data': base64.b64encode(cert),
                    'client-key-data': base64.b64encode(key)
                }
            }
        ]
        mock_yaml.return_value = kubeconfig

        # and now, with the kubeconfig complete and parsable, we should get all the expected k8s keys
        is_keys = ["kubernetes-client-ca", "kubernetes-client-cert", "kubernetes-client-key", "kubernetes-endpoint"]
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data='{"notyaml": True}')):
            self.assertTrue(set(is_keys).issubset(list(self.obj.is_k3s_running('1.1.1.1').keys())),
                            'Received k3s details even though the k3s config cannot be parsed')

    @mock.patch('agent.common.NuvlaBoxCommon.run')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.is_k3s_running')
    def test_infer_if_additional_coe_exists(self, mock_k3s, mock_run):
        # if we timeout GREPing for a k8s process, we get {}
        mock_run.side_effect = subprocess.TimeoutExpired('', 0)
        self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
                         'Got additional COE details even though the PID check failed')

        mock_run.assert_called_once()
        mock_k3s.assert_not_called()

        # or if the grep result is empty/None, we try to get k3s
        grep = mock.MagicMock()
        grep.stdout = ''
        mock_run.return_value = grep
        mock_run.reset_mock(side_effect=True)

        mock_k3s.return_value = {'fake-k3s': True}
        self.assertEqual(self.obj.infer_if_additional_coe_exists(), {'fake-k3s': True},
                         'Failed to get additional k3s IS when kube-apiserver PID does not exist')
        mock_k3s.assert_called_once_with(None)

        # and we get {} again if also the k3s discovery raises an exception
        mock_k3s.side_effect = TimeoutError
        self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
                         'Got additional COE details even though there is not Kubernetes installation available')

        # if we get a kube PID though, then we try to infer its args to build the IS payload
        grep.stdout = '/fake/proc/pid/comm:foo'
        mock_run.return_value = grep

        k8s_process = 'exec\x00--arg1=1\n--arg2=2\x00--arg3=3\x00'
        # if an exception is thrown while opening the process cmdline file, we get {}
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data=k8s_process)) as mock_open:
            mock_open.side_effect = FileNotFoundError
            self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
                             'Got additional COE details even though the k8s process cmdline file does not exist')

        # if the file exists, we read it but if it hasn't the right keywords, we get {} again
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data=k8s_process)):
            self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
                             'Got additional COE details even though the k8s process cmdline is missing the right args')

        # finally, if the cmdline args are all there, we should get the whole kubernetes IS payload
        k8s_cmdline_keys = ["advertise-address", "secure-port", "client-ca-file",
                            "kubelet-client-certificate", "kubelet-client-key"]

        k8s_process = 'exec\n--' + '=fake_value\x00--'.join(k8s_cmdline_keys) + '=1\n'
        is_fields = ['kubernetes-endpoint', 'kubernetes-client-ca', 'kubernetes-client-cert', 'kubernetes-client-key']
        with mock.patch(self.agent_nuvlabox_common_open, mock.mock_open(read_data=k8s_process)):
            self.assertTrue(set(is_fields).issubset(list(self.obj.infer_if_additional_coe_exists().keys())),
                            'Got unexpected K8s COE IS fields')

    @mock.patch('docker.models.containers.ContainerCollection.list')
    def test_get_all_nuvlabox_components(self, mock_containers_list):
        mock_containers_list.return_value = [fake.MockContainer(myid='fake-container')]
        self.assertEqual(self.obj.get_all_nuvlabox_components(), ['fake-container'],
                         'Failed to get all NuvlaBox containers')