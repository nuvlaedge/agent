#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import docker
import logging
import mock
import requests
import unittest
import tests.utils.fake as fake
import agent.common.NuvlaBoxCommon as NuvlaBoxCommon


class ContainerRuntimeDockerTestCase(unittest.TestCase):

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
        with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data=tcp_file)):
            self.assertEqual(self.obj.get_api_ip_port(), ('192.168.40.45', 5000),
                             'Could not get valid IP from filesystem')

        # if there's no valid IP in this file, then we return 127.0.0.1
        tcp_file = '''sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:0B83 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22975 1 ffffffc1dea20000 100 0 0 10 0                     
   1: 00000000:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 46922 1 ffffffc1c9be1740 100 0 0 10 0
   '''
        with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data=tcp_file)):
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
        self.assertGreater(len(err), 1,
                           "There should have been Memory collection errors since fields are missing")
