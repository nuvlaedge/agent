#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Common

List of common attributes for all classes
"""

import os
import json
import fcntl
import socket
import struct
import logging
import argparse
import sys
import requests
import signal
import string
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from nuvla.api import Api
from subprocess import PIPE, Popen

KUBERNETES_SERVICE_HOST = os.getenv('KUBERNETES_SERVICE_HOST')
if KUBERNETES_SERVICE_HOST:
    from kubernetes import client, config
    ORCHESTRATOR = 'kubernetes'
    ORCHESTRATOR_COE = ORCHESTRATOR
else:
    import docker
    ORCHESTRATOR = 'docker'
    ORCHESTRATOR_COE = 'swarm'


def get_mac_address(ifname, separator=':'):
    """ Gets the MAC address for interface ifname """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
        mac = ':'.join('%02x' % b for b in info[18:24])
        return mac
    except struct.error:
        logging.error("Could not find the device's MAC address from the network interface {} in {}".format(ifname, s))
        raise
    except TypeError:
        logging.error("The MAC address could not be parsed")
        raise


def get_log_level(args):
    """ Sets log level based on input args """

    if args.debug:
        return logging.DEBUG
    elif args.quiet:
        return logging.CRITICAL
    return logging.INFO


def logger(log_level):
    """ Configures logging """

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    stdout_handler = logging.StreamHandler(sys.stdout)
    root_logger.addHandler(stdout_handler)

    return root_logger


def arguments():
    """ Builds a generic argparse

    :return: parser
    """

    parser = argparse.ArgumentParser(description='NuvlaBox Agent')
    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true')
    parser.add_argument('-q', '--quiet', dest='quiet', default=False, action='store_true')

    return parser


def raise_timeout(signum, frame):
    raise TimeoutError


@contextmanager
def timeout(time):
    # Register a function to raise a TimeoutError on the signal.
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after ``time``.
    signal.alarm(time)

    try:
        yield
    except TimeoutError:
        pass
    finally:
        # Unregister the signal so it won't be triggered
        # if the timeout is not reached.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)


class ContainerRuntimeClient(ABC):
    """
    Base abstract class for the Docker and Kubernetes clients
    """

    @abstractmethod
    def __init__(self, host_rootfs, host_home):
        self.client = None
        self.hostfs = host_rootfs
        self.job_engine_lite_component = "nuvlabox-job-engine-lite"
        self.job_engine_lite_image = None
        self.vpn_client_component = 'vpn-client'
        self.host_home = host_home

    @abstractmethod
    def get_node_info(self):
        """
        Get high level info about the hosting node
        """
        pass

    @abstractmethod
    def get_host_os(self):
        """
        Get operating system of the hosting node
        """
        pass

    @abstractmethod
    def get_join_tokens(self):
        """
        Get token for joining this node
        """
        pass

    @abstractmethod
    def list_nodes(self, optional_filter={}):
        """
        List all the nodes in the cluster
        """
        pass

    @abstractmethod
    def get_cluster_info(self, default_cluster_name=None):
        """
        Get information about the cluster
        """
        pass

    @abstractmethod
    def get_api_ip_port(self):
        """
        Get the full API endpoint
        """
        pass

    @abstractmethod
    def has_pull_job_capability(self):
        """
        Checks if NuvlaBox supports pull mode for jobs
        """
        pass

    @abstractmethod
    def get_node_labels(self):
        """
        Collects the labels from the hosting node
        """
        pass

    @staticmethod
    def cast_dict_to_list(key_value_dict):
        """
        Parses a set of key value pairs in a dict, into a list of strings
        :param key_value_dict: something like {'key': value, 'novalue': None, ...}
        :return: ["key=value", "novalue", ...]
        """

        final_list = []
        for label, value in key_value_dict.items():
            if value:
                final_list.append("{}={}".format(label, value))
            else:
                final_list.append(label)

        return final_list

    @abstractmethod
    def is_vpn_client_running(self):
        """
        Checks if the vpn-client component is up and running
        """
        pass

    @abstractmethod
    def install_ssh_key(self, ssh_pub_key, ssh_folder):
        """
        Takes an SSH public key and adds it to the host's HOME authorized keys (aka ssh_folder)
        """
        pass

    @abstractmethod
    def is_nuvla_job_running(self, job_id, job_execution_id):
        """
        Finds if a job is still running
        :param job_id: nuvla ID of the job
        :param job_execution_id: container ID of the job
        """
        pass

    @abstractmethod
    def launch_job(self, job_id, job_execution_id, nuvla_endpoint,
                   nuvla_endpoint_insecure=False, api_key=None, api_secret=None, docker_image=None):
        """
        Launches a new job
        :param job_id: nuvla ID of the job
        :param job_execution_id: name of the container/pod
        :param nuvla_endpoint: Nuvla endpoint
        :param nuvla_endpoint_insecure: whether to use TLS or not
        :param api_key: API key credential for the job to access Nuvla
        :param api_secret: secret for the api_key
        """
        pass

    @abstractmethod
    def collect_container_metrics(self):
        """
        Scans all visible containers and reports their resource consumption
        :return:
        """
        pass

    @abstractmethod
    def get_installation_parameters(self, search_label):
        """
        Scans all the NuvlaBox components and returns all parameters that are relevant to the installation of the NB
        :param search_label: label to be used for searching the components
        """
        pass

    @abstractmethod
    def read_system_issues(self, node_info):
        """
        Checks if the underlying container management system is reporting any errors or warnings
        :param node_info: the result of self.get_node_info()
        """
        pass

    @abstractmethod
    def get_node_id(self, node_info):
        """
        Retrieves the node ID
        :param node_info: the result of self.get_node_info()
        """
        pass

    @abstractmethod
    def get_cluster_id(self, node_info, default_cluster_name=None):
        """
        Gets the cluster ID
        :param node_info: the result of self.get_node_info()
        :param default_cluster_name: default cluster name in case an ID is not found
        """
        pass

    @abstractmethod
    def get_cluster_managers(self):
        """
        Retrieves the cluster manager nodes
        """
        pass

    @abstractmethod
    def get_host_architecture(self, node_info):
        """
        Retrieves the host system arch
        :param node_info: the result of self.get_node_info()
        """
        pass

    @abstractmethod
    def get_hostname(self, node_info=None):
        """
        Retrieves the hostname
        :param node_info: the result of self.get_node_info()
        """
        pass

    @abstractmethod
    def get_cluster_join_address(self, node_id):
        """
        Retrieved the IP address of a manager that can be joined for clustering actions
        :param node_id: ID of the node
        """
        pass

    @abstractmethod
    def is_node_active(self, node):
        """
        Checks if a cluster node is ready/active
        :param node: Node object, from self.list_nodes()
        """
        pass

    @abstractmethod
    def get_container_plugins(self):
        """
        Lists the container plugins installed in the system
        """
        pass


class KubernetesClient(ContainerRuntimeClient):
    """
    Kubernetes client
    """

    def __init__(self, host_rootfs, host_home):
        super().__init__(host_rootfs, host_home)

        config.load_incluster_config()
        self.client = client.CoreV1Api()
        self.client_apps = client.AppsV1Api()
        self.namespace = os.getenv('MY_NAMESPACE', 'nuvlabox')
        self.job_engine_lite_image = os.getenv('NUVLABOX_JOB_ENGINE_LITE_IMAGE')
        self.host_node_ip = os.getenv('MY_HOST_NODE_IP')
        self.host_node_name = os.getenv('MY_HOST_NODE_NAME')
        self.vpn_client_component = os.getenv('NUVLABOX_VPN_COMPONENT_NAME', 'vpn-client')

    def get_node_info(self):
        if self.host_node_name:
            this_node = self.client.read_node(self.host_node_name)
            try:
                return this_node.status.node_info
            except AttributeError:
                logging.warning(f'Cannot infer node information for node "{self.host_node_name}"')

        return None

    def get_host_os(self):
        node_info = self.get_node_info()
        if node_info:
            return f"{node_info.os_image} {node_info.kernel_version}"

        return None

    def get_join_tokens(self):
        # NOTE: I don't think we can get the cluster join token from the API
        # it needs to come from the cluster mgmt tool (i.e. k0s, k3s, kubeadm, etc.)
        return None

    def list_nodes(self, optional_filter={}):
        return self.client.list_node().items

    def get_cluster_info(self, default_cluster_name=None):
        node_info = self.get_node_info()

        cluster_id = self.get_cluster_id(node_info, default_cluster_name)

        nodes = self.list_nodes()
        managers = []
        workers = []
        for n in nodes:
            for label in n.metadata.labels:
                if 'node-role' in label and 'master' in label:
                    managers.append(n.metadata.name)
                else:
                    workers.append(n.metadata.name)

        return {
            'cluster-id': cluster_id,
            'cluster-orchestrator': ORCHESTRATOR_COE,
            'cluster-managers': managers,
            'cluster-workers': workers
        }

    def get_api_ip_port(self):
        endpoints = self.client.list_endpoints_for_all_namespaces().items

        ip_port = 6443
        if self.host_node_ip:
            return self.host_node_ip, ip_port
        else:
            for endpoint in endpoints:
                if endpoint.metadata.name.lower() == 'kubernetes':
                    for subset in endpoint.subsets:
                        for addr in subset.addresses:
                            if addr.ip:
                                self.host_node_ip = addr.ip
                                break

                        for port in subset.ports:
                            if port.name == 'https' and port.protocol == 'TCP':
                                ip_port = port.port
                                break

                        if self.host_node_ip and ip_port:
                            return self.host_node_ip, ip_port

                    break

        return None, None

    def has_pull_job_capability(self):
        if self.job_engine_lite_image:
            return True
        else:
            return False

    def get_node_labels(self):
        node = self.get_node_info()
        node_labels = node.metadata.labels

        return self.cast_dict_to_list(node_labels)

    def is_vpn_client_running(self):
        vpn_pod = self.client.list_pod_for_all_namespaces(label_selector=f"component={self.vpn_client_component}").items

        if len(vpn_pod) < 1:
            return False

        for res in vpn_pod:
            for container in res.status.container_statuses:
                if container.name == self.vpn_client_component and container.ready:
                    return True

        return False

    def install_ssh_key(self, ssh_pub_key, ssh_folder):
        name = 'nuvlabox-ssh-installer'
        try:
            existing_pod = self.client.read_namespaced_pod(namespace=self.namespace, name=name)
        except client.exceptions.ApiException as e:
            if e.status == 404:
                # this is good, we can proceed
                pass
            else:
                raise
        else:
            if existing_pod.status.phase.lower() not in ['succeeded', 'running']:
                logging.warning(f'Found old {name} with state {existing_pod.status.phase}. Trying to relaunch it...')
                self.client.delete_namespaced_pod(namespace=self.namespace, name=name)
            else:
                logging.info(f'SSH key installer "{name}" has already been launched in the past. Skipping this step')
                return False

        cmd = ["sh", "-c", "echo -e \"${SSH_PUB}\" >> %s" % f'{ssh_folder}/authorized_keys']
        volume_name = f'{name}-volume'
        pod_body = client.V1Pod(
            kind='Pod',
            metadata=client.V1ObjectMeta(name=name),
            spec=client.V1PodSpec(
                node_name=self.host_node_name,
                volumes=[
                    client.V1Volume(
                        name=volume_name,
                        host_path=client.V1HostPathVolumeSource(
                            path=f'{self.host_home}/.ssh'
                        )
                    )
                ],
                restart_policy='Never',
                containers=[
                    client.V1Container(
                        name=name,
                        image='alpine',
                        env=[
                            client.V1EnvVar(
                                name='SSH_PUB',
                                value=ssh_pub_key
                            )
                        ],
                        volume_mounts=[
                            client.V1VolumeMount(
                                name=volume_name,
                                mount_path=ssh_folder
                            )
                        ],
                        command=cmd
                    )
                ]
            )
        )

        self.client.create_namespaced_pod(namespace=self.namespace, body=pod_body)

        return True

    def is_nuvla_job_running(self, job_id, job_execution_id):
        try:
            job = self.client.read_namespaced_pod(namespace=self.namespace, name=job_execution_id)
        except client.exceptions.ApiException as e:
            if e.status == 404:
                return False
            else:
                logging.error(f'Cannot handle job {job_id}. Reason: {str(e)}')
                # assume it is running so we don't mess anything
                return True

        try:
            if job.status.phase.lower() == 'running':
                logging.info(f'Job {job_id} is already running in pod {job.metadata.name}, with UID {job.metadata.uid}')
                return True
            elif job.status.phase.lower() == 'pending':
                logging.warning(f'Job {job_id} was created and still pending')
                # TODO: maybe we should run a cleanup for pending jobs after X hours
            else:
                if job.status.phase.lower() == 'succeeded':
                    logging.info(f'Job {job_id} has already finished successfully. Deleting the pod...')
                # then it is probably UNKNOWN or in an undesired state
                self.client.delete_namespaced_pod(namespace=self.namespace, name=job_execution_id)
        except AttributeError:
            # assume it is running so we don't mess anything
            return True
        except client.exceptions.ApiException as e:
            # this exception can only happen if we tried to delete the pod and couldn't
            # log it and don't let another job come in
            logging.error(f'Failed to handle job {job_id} due to pod management error: {str(e)}')
            return True

        return False

    def launch_job(self, job_id, job_execution_id, nuvla_endpoint,
                   nuvla_endpoint_insecure=False, api_key=None, api_secret=None, docker_image=None):

        cmd = f'-- /app/job_executor.py --api-url https://{nuvla_endpoint} ' \
            f'--api-key {api_key} ' \
            f'--api-secret {api_secret} ' \
            f'--job-id {job_id}'

        if nuvla_endpoint_insecure:
            cmd = f'{cmd} --api-insecure'

        img = docker_image if docker_image else self.job_engine_lite_image
        logging.info(f'Starting job {job_id} from {img}, with command: "{cmd}"')

        pod_body = client.V1Pod(
            kind='Pod',
            metadata=client.V1ObjectMeta(name=job_execution_id),
            spec=client.V1PodSpec(
                node_name=self.host_node_name,
                restart_policy='Never',
                containers=[
                    client.V1Container(
                        name=job_execution_id,
                        image=img,
                        command=cmd
                    )
                ]
            )
        )

        self.client.create_namespaced_pod(namespace=self.namespace, body=pod_body)

    def collect_container_metrics(self):
        pods_here = self.client.list_pod_for_all_namespaces(field_selector=f'spec.nodeName={self.host_node_name}')
        pods_here_per_name = {f'{p.metadata.namespace}/{p.metadata.name}': p for p in pods_here.items}

        this_node_capacity = self.get_node_info().status.capacity
        node_cpu_capacity = int(this_node_capacity['cpu'])
        node_mem_capacity = int(this_node_capacity['memory'].rstrip('Ki'))

        out = []
        pod_metrics_list = client.CustomObjectsApi().list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods")

        items = pod_metrics_list.get('items', [])
        for pod in items:
            short_identifier = f"{pod['metadata']['namespace']}/{pod['metadata']['name']}"
            if short_identifier not in pods_here_per_name:
                continue

            for container in pod.get('containers', []):
                metrics = {
                    'id': pod['metadata']['selfLink'],
                    'name': container['name']
                }
                container_cpu_usage = int(container['usage']['cpu'].rstrip('n'))
                # units come in nanocores
                metrics['cpu-percent'] = "%.2f" % round(container_cpu_usage*100/(node_cpu_capacity*1000000000), 2)

                container_mem_usage = int(container['usage']['memory'].rstrip('Ki'))
                # units come in Ki
                metrics['mem-percent'] = "%.2f" % round(container_mem_usage*100/node_mem_capacity, 2)

                for cstat in pods_here_per_name[short_identifier].status.container_statuses:
                    if cstat.name == container['name']:
                        for k, v in cstat.state.to_dict().items():
                            if v:
                                metrics['container-status'] = k
                                break

                        container['restart-count'] = int(cstat.restart_count)

                out.append(metrics)

        return out

    def get_installation_parameters(self, search_label):
        nuvlabox_deployments = self.client_apps.list_namespaced_deployment(namespace=self.namespace,
                                                                           label_selector=search_label).items

        environment = []
        for dep in nuvlabox_deployments:
            dep_containers = dep.spec.template.spec.containers
            for container in dep_containers:
                try:
                    env = container.env
                    for env_var in env:
                        if env_var.value_from:
                            # this is a templated var. No need to report it
                            continue

                        environment.append(f'{env_var.name}={env_var.value}')
                except AttributeError:
                    continue

        unique_env = list(filter(None, set(environment)))

        return {'project-name': self.namespace,
                'environment': unique_env}

    def read_system_issues(self, node_info):
        errors = []
        warnings = []
        # TODO: is there a way to get any system errors from the k8s API?
        # The cluster-info dump reports a lot of stuff but is all verbose

        return errors, warnings

    def get_node_id(self, node_info):
        return node_info.metadata.name

    def get_cluster_id(self, node_info, default_cluster_name=None):
        cluster_id = default_cluster_name
        cluster_name = node_info.metadata.cluster_name
        if cluster_name:
            cluster_id = cluster_name

        return cluster_id

    def get_cluster_managers(self):
        managers = []
        for n in self.list_nodes():
            for label in n.metadata.labels:
                if 'node-role' in label and 'master' in label:
                    managers.append(n.metadata.name)

        return managers

    def get_host_architecture(self, node_info):
        return node_info.status.node_info.architecture

    def get_hostname(self, node_info=None):
        return self.host_node_name

    def get_kubelet_version(self):
        # IMPORTANT: this is only implemented for this k8s client class
        return self.get_node_info().status.node_info.kubelet_version

    def get_cluster_join_address(self, node_id):
        # NOT IMPLEMENTED for k8s installations
        pass

    def is_node_active(self, node):
        if any(list(map(lambda n: n.type == 'Ready' and n.status == 'True', node.status.conditions))):
            return node.metadata.name

        return None

    def get_container_plugins(self):
        # TODO
        # doesn't seem to be available from the API
        return []


#
class DockerClient(ContainerRuntimeClient):
    """
    Docker client
    """

    def __init__(self, host_rootfs, host_home):
        super().__init__(host_rootfs, host_home)
        self.client = docker.from_env()
        self.lost_quorum_hint = 'possible that too few managers are online'

    def get_node_info(self):
        return self.client.info()

    def get_host_os(self):
        node_info = self.get_node_info()
        return f"{node_info['OperatingSystem']} {node_info['KernelVersion']}"

    def get_join_tokens(self):
        try:
            if self.client.swarm.attrs:
                return self.client.swarm.attrs['JoinTokens']['Manager'], \
                       self.client.swarm.attrs['JoinTokens']['Worker']
        except docker.errors.APIError as e:
            if self.lost_quorum_hint in str(e):
                # quorum is lost
                logging.warning(f'Quorum is lost. This node will no longer support Service and Cluster management')

        return None

    def list_nodes(self, optional_filter={}):
        return self.client.nodes.list(filters=optional_filter)

    def get_cluster_info(self, default_cluster_name=None):
        node_info = self.get_node_info()
        swarm_info = node_info['Swarm']

        if swarm_info.get('ControlAvailable'):
            cluster_id = swarm_info.get('Cluster', {}).get('ID')
            managers = []
            workers = []
            for manager in self.list_nodes(optional_filter={'role': 'manager'}):
                if manager not in managers and manager.attrs.get('Status', {}).get('State', '').lower() == 'ready':
                    managers.append(manager.id)

            for worker in self.list_nodes(optional_filter={'role': 'worker'}):
                if worker not in workers and worker.attrs.get('Status', {}).get('State', '').lower() == 'ready':
                    workers.append(worker.id)

            return {
                'cluster-id': cluster_id,
                'cluster-orchestrator': ORCHESTRATOR_COE,
                'cluster-managers': managers,
                'cluster-workers': workers
            }
        else:
            return {}

    def get_api_ip_port(self):
        node_info = self.get_node_info()

        ip = node_info.get("Swarm", {}).get("NodeAddr")
        if not ip:
            # then probably this isn't running in Swarm mode
            try:
                ip = None
                with open(f'{self.hostfs}/proc/net/tcp') as ipfile:
                    ips = ipfile.readlines()
                    for line in ips[1:]:
                        cols = line.strip().split(' ')
                        if cols[1].startswith('00000000') or cols[2].startswith('00000000'):
                            continue
                        hex_ip = cols[1].split(':')[0]
                        ip = f'{int(hex_ip[len(hex_ip)-2:],16)}.' \
                            f'{int(hex_ip[len(hex_ip)-4:len(hex_ip)-2],16)}.' \
                            f'{int(hex_ip[len(hex_ip)-6:len(hex_ip)-4],16)}.' \
                            f'{int(hex_ip[len(hex_ip)-8:len(hex_ip)-6],16)}'
                        break
                if not ip:
                    raise Exception('Cannot infer IP')
            except:
                ip = '127.0.0.1'
            else:
                if not ip:
                    logging.warning("Cannot infer the NuvlaBox API IP!")
                    return None, 5000

        return ip, 5000

    def has_pull_job_capability(self):
        try:
            container = self.client.containers.get(self.job_engine_lite_component)
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logging.error(f"Unable to search for container {self.job_engine_lite_component}. Reason: {str(e)}")
            return False

        try:
            if container.status.lower() == "paused":
                self.job_engine_lite_image = container.attrs['Config']['Image']
                return True
        except (AttributeError, KeyError):
            return False

        return False

    def get_node_labels(self):
        try:
            node_id = self.get_node_info()["Swarm"]["NodeID"]
            node_labels = self.client.api.inspect_node(node_id)["Spec"]["Labels"]
        except (KeyError, docker.errors.APIError, docker.errors.NullResource) as e:
            if not "node is not a swarm manager" in str(e).lower():
                logging.debug(f"Cannot get node labels: {str(e)}")
            return []

        return self.cast_dict_to_list(node_labels)

    def is_vpn_client_running(self):
        vpn_client_running = True if self.client.containers.get("vpn-client").status == 'running' else False
        return vpn_client_running

    def install_ssh_key(self, ssh_pub_key, ssh_folder):
        cmd = "sh -c 'echo -e \"${SSH_PUB}\" >> %s'" % f'{ssh_folder}/authorized_keys'

        self.client.containers.run('alpine',
                                   remove=True,
                                   command=cmd,
                                   environment={
                                       'SSH_PUB': ssh_pub_key
                                   },
                                   volumes={
                                       f'{self.host_home}/.ssh': {
                                           'bind': ssh_folder
                                       }})

        return True

    def is_nuvla_job_running(self, job_id, job_execution_id):
        try:
            job_container = self.client.containers.get(job_execution_id)
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logging.error(f'Cannot handle job {job_id}. Reason: {str(e)}')
            # assume it is running so we don't mess anything
            return True

        try:
            if job_container.status.lower() in ['running', 'restarting']:
                logging.info(f'Job {job_id} is already running in container {job_container.name}')
                return True
            elif job_container.status.lower() in ['created']:
                logging.warning(f'Job {job_id} was created by not started. Removing it and starting a new one')
                job_container.remove()
            else:
                # then it is stopped or dead. force kill it and re-initiate
                job_container.kill()
        except AttributeError:
            # assume it is running so we don't mess anything
            return True
        except docker.errors.NotFound:
            # then it stopped by itself...maybe it ran already and just finished
            # let's not do anything just in case this is a late coming job. In the next telemetry cycle, if job is there
            # again, then we run it because this container is already gone
            return True

        return False

    def launch_job(self, job_id, job_execution_id, nuvla_endpoint,
                   nuvla_endpoint_insecure=False, api_key=None, api_secret=None,
                   docker_image=None):
        # Get the compute-api network
        try:
            compute_api = self.client.containers.get('compute-api')
            local_net = list(compute_api.attrs['NetworkSettings']['Networks'].keys())[0]
        except:
            logging.error(f'Cannot infer compute-api network for local job {job_id}')
            return

        cmd = f'-- /app/job_executor.py --api-url https://{nuvla_endpoint} ' \
            f'--api-key {api_key} ' \
            f'--api-secret {api_secret} ' \
            f'--job-id {job_id}'

        if nuvla_endpoint_insecure:
            cmd = f'{cmd} --api-insecure'

        logging.info(f'Starting job {job_id} inside {self.job_engine_lite_image} container, with command: "{cmd}"')

        img = docker_image if docker_image else self.job_engine_lite_image
        self.client.containers.run(img,
                                   command=cmd,
                                   detach=True,
                                   name=job_execution_id,
                                   hostname=job_execution_id,
                                   remove=True,
                                   network=local_net,
                                   volumes={
                                       '/var/run/docker.sock': {
                                           'bind': '/var/run/docker.sock',
                                           'mode': 'ro'
                                       }
                                   })

        try:
            # for some jobs (like clustering), it is better if the job container is also in the default bridge
            # network, so it doesn't get affected by network changes in the NuvlaBox
            self.client.api.connect_container_to_network(job_execution_id, 'bridge')
        except Exception as e:
            logging.warning(f'Could not attach {job_execution_id} to bridge network: {str(e)}')

    def collect_container_metrics(self):
        docker_stats = []

        all_containers = self.client.containers.list()
        for container in all_containers:
            docker_stats.append(self.client.api.stats(container.id))

        # get first samples (needed for cpu monitoring)
        old_cpu = []
        for c_stat in docker_stats:
            container_stats = json.loads(next(c_stat))

            try:
                old_cpu.append((float(container_stats["cpu_stats"]["cpu_usage"]["total_usage"]),
                                float(container_stats["cpu_stats"]["system_cpu_usage"])))
            except KeyError:
                old_cpu.append((0.0, 0.0))

        # now the actual monitoring
        out = []
        for i, c_stat in enumerate(docker_stats):
            container = all_containers[i]
            container_stats = json.loads(next(c_stat))

            #
            # -----------------
            # CPU
            try:
                cpu_total = float(container_stats["cpu_stats"]["cpu_usage"]["total_usage"])
                cpu_system = float(container_stats["cpu_stats"]["system_cpu_usage"])

                online_cpus = container_stats["cpu_stats"] \
                    .get("online_cpus", len(container_stats["cpu_stats"]["cpu_usage"].get("percpu_usage", -1)))

                cpu_delta = cpu_total - old_cpu[i][0]
                system_delta = cpu_system - old_cpu[i][1]

                cpu_percent = 0.0
                if system_delta > 0.0 and online_cpus > -1:
                    cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0
            except (IndexError, KeyError, ValueError, ZeroDivisionError) as e:
                logging.error(f"Cannot get CPU stats for container {container.name}: {str(e)}. Moving on")
                cpu_percent = 0.0

            #
            # -----------------
            # MEM
            try:
                mem_usage = float(container_stats["memory_stats"]["usage"] / 1024 / 1024)
                mem_limit = float(container_stats["memory_stats"]["limit"] / 1024 / 1024)
                if round(mem_limit, 2) == 0.00:
                    mem_percent = 0.00
                else:
                    mem_percent = round(float(mem_usage / mem_limit) * 100, 2)
            except (IndexError, KeyError, ValueError) as e:
                logging.error(f"Cannot get Mem stats for container {container.name}: {str(e)}. Moving on")
                mem_percent = mem_usage = mem_limit = 0.00

            #
            # -----------------
            # NET
            net_in = net_out = 0.0
            if "networks" in container_stats:
                net_in = sum(container_stats["networks"][iface]["rx_bytes"]
                             for iface in container_stats["networks"]) / 1000 / 1000
                net_out = sum(container_stats["networks"][iface]["tx_bytes"]
                              for iface in container_stats["networks"]) / 1000 / 1000

            #
            # -----------------
            # BLOCK
            io_bytes_recursive = container_stats.get("blkio_stats", {}).get("io_service_bytes_recursive", [])
            if io_bytes_recursive:
                try:
                    blk_in = float(io_bytes_recursive[0]["value"] / 1000 / 1000)
                except Exception as e:
                    logging.error(f"Cannot get blk_in stats for container {container.name}: {str(e)}. Moving on")
                    blk_in = 0.0

                try:
                    blk_out = float(io_bytes_recursive[1]["value"] / 1000 / 1000)
                except Exception as e:
                    logging.error(f"Cannot get blk_out stats for container {container.name}: {str(e)}. Moving on")
                    blk_out = 0.0
            else:
                blk_out = blk_in = 0.0

            # -----------------
            out.append({
                'id': container.id,
                'name': container.name,
                'container-status': container.status,
                'cpu-percent': "%.2f" % round(cpu_percent, 2),
                'mem-usage-limit': "%sMiB / %sGiB" % (round(mem_usage, 2), round(mem_limit / 1024, 2)),
                'mem-percent': "%.2f" % mem_percent,
                'net-in-out': "%sMB / %sMB" % (round(net_in, 2), round(net_out, 2)),
                'blk-in-out': "%sMB / %sMB" % (round(blk_in, 2), round(blk_out, 2)),
                'restart-count': int(container.attrs["RestartCount"]) if "RestartCount" in container.attrs else 0
            })

        return out

    def get_installation_parameters(self, search_label):
        nuvlabox_containers = self.client.containers.list(filters={'label': search_label})

        try:
            myself = self.client.containers.get(socket.gethostname())
        except docker.errors.NotFound:
            logging.error(f'Cannot find this container by hostname: {socket.gethostname()}. Cannot proceed')
            raise

        config_files = myself.labels.get('com.docker.compose.project.config_files', '').split(',')
        working_dir = myself.labels['com.docker.compose.project.working_dir']
        project_name = myself.labels['com.docker.compose.project']
        environment = myself.attrs.get('Config', {}).get('Env', [])
        for container in nuvlabox_containers:
            c_labels = container.labels
            if c_labels.get('com.docker.compose.project', '') == project_name and \
                    c_labels.get('com.docker.compose.project.working_dir', '') == working_dir and \
                    container.id != myself.id:
                config_files += c_labels.get('com.docker.compose.project.config_files', '').split(',')
                environment += container.attrs.get('Config', {}).get('Env', [])

        unique_config_files = list(filter(None, set(config_files)))
        unique_env = list(filter(None, set(environment)))

        if working_dir and project_name and unique_config_files:
            return {'project-name': project_name,
                    'working-dir': working_dir,
                    'config-files': unique_config_files,
                    'environment': unique_env}
        else:
            return None

    def read_system_issues(self, node_info):
        errors = []
        warnings = []
        if node_info.get('Swarm', {}).get('Error'):
            errors.append(node_info.get('Swarm', {}).get('Error'))

        if node_info.get('Warnings'):
            warnings += node_info.get('Warnings')

        return errors, warnings

    def get_node_id(self, node_info):
        return node_info.get("Swarm", {}).get("NodeID")

    def get_cluster_id(self, node_info, default_cluster_name=None):
        return node_info.get('Swarm', {}).get('Cluster', {}).get('ID')

    def get_cluster_managers(self):
        remote_managers = self.get_node_info().get('Swarm', {}).get('RemoteManagers')
        cluster_managers = []
        if remote_managers and isinstance(remote_managers, list):
            cluster_managers = [rm.get('NodeID') for rm in remote_managers]

        return cluster_managers

    def get_host_architecture(self, node_info):
        return node_info["Architecture"]

    def get_hostname(self, node_info=None):
        return node_info["Name"]

    def get_cluster_join_address(self, node_id):
        for manager in self.get_node_info().get('Swarm', {}).get('RemoteManagers'):
            if node_id == manager.get('NodeID', ''):
                try:
                    return manager['Addr']
                except KeyError:
                    logging.warning(f'Unable to infer cluster-join-address attribute: {manager}')

        return None

    def is_node_active(self, node):
        if node.attrs.get('Status', {}).get('State', '').lower() == 'ready':
            return node.id

        return None

    def get_container_plugins(self):
        all_plugins = self.client.plugins.list()

        enabled_plugins = []
        for plugin in all_plugins:
            if plugin.enabled:
                enabled_plugins.append(plugin.name)

        return enabled_plugins


# --------------------
class NuvlaBoxCommon():
    """ Common set of methods and variables for the NuvlaBox agent
    """
    def __init__(self, shared_data_volume="/srv/nuvlabox/shared"):
        """ Constructs an Infrastructure object, with a status placeholder

        :param shared_data_volume: shared volume target path
        """

        self.data_volume = shared_data_volume
        self.docker_socket_file = '/var/run/docker.sock'
        self.hostfs = "/rootfs"
        self.ssh_pub_key = os.environ.get('NUVLABOX_IMMUTABLE_SSH_PUB_KEY')
        self.host_user_home_file = f'{self.data_volume}/.host_user_home'
        if os.path.exists(self.host_user_home_file):
            with open(self.host_user_home_file) as userhome:
                self.installation_home = userhome.read().strip()
        else:
            self.installation_home = os.environ.get('HOST_HOME')

            if not self.installation_home:
                logging.error('Host user HOME directory not defined. This might impact future SSH management actions')
            else:
                with open(self.host_user_home_file, 'w') as userhome:
                    userhome.write(self.installation_home)

        nuvla_endpoint_raw = None
        nuvla_endpoint_insecure_raw = None
        self.nuvla_endpoint_key = 'NUVLA_ENDPOINT'
        self.nuvla_endpoint_insecure_key = 'NUVLA_ENDPOINT_INSECURE'
        self.nuvlabox_nuvla_configuration = f'{self.data_volume}/.nuvla-configuration'

        if os.path.exists(self.nuvlabox_nuvla_configuration):
            with open(self.nuvlabox_nuvla_configuration) as nuvla_conf:
                for line in nuvla_conf.read().split():
                    try:
                        if line:
                            line_split = line.split('=')
                            if self.nuvla_endpoint_key == line_split[0]:
                                nuvla_endpoint_raw = line_split[1]
                            if self.nuvla_endpoint_insecure_key == line_split[0]:
                                nuvla_endpoint_insecure_raw = bool(line_split[1])
                    except IndexError:
                        pass

        if not nuvla_endpoint_raw:
            nuvla_endpoint_raw = os.environ["NUVLA_ENDPOINT"] if "NUVLA_ENDPOINT" in os.environ else "nuvla.io"

        while nuvla_endpoint_raw[-1] == "/":
            nuvla_endpoint_raw = nuvla_endpoint_raw[:-1]

        self.nuvla_endpoint = nuvla_endpoint_raw.replace("https://", "")

        if not nuvla_endpoint_insecure_raw:
            nuvla_endpoint_insecure_raw = os.environ["NUVLA_ENDPOINT_INSECURE"] if "NUVLA_ENDPOINT_INSECURE" in os.environ else False

        if isinstance(nuvla_endpoint_insecure_raw, str):
            if nuvla_endpoint_insecure_raw.lower() == "false":
                nuvla_endpoint_insecure_raw = False
            else:
                nuvla_endpoint_insecure_raw = True
        else:
            nuvla_endpoint_insecure_raw = bool(nuvla_endpoint_insecure_raw)

        self.nuvla_endpoint_insecure = nuvla_endpoint_insecure_raw

        if ORCHESTRATOR == 'kubernetes':
            self.container_runtime = KubernetesClient(self.hostfs, self.installation_home)
        else:
            if os.path.exists(self.docker_socket_file):
                self.container_runtime = DockerClient(self.hostfs, self.installation_home)
            else:
                raise Exception(f'Orchestrator is "{ORCHESTRATOR}", but file {self.docker_socket_file} is not present')

        self.activation_flag = "{}/.activated".format(self.data_volume)
        self.swarm_manager_token_file = "swarm-manager-token"
        self.swarm_worker_token_file = "swarm-worker-token"
        self.commissioning_file = ".commission"
        self.status_file = ".status"
        self.status_notes_file = ".status_notes"
        self.nuvlabox_status_file = "{}/.nuvlabox-status".format(self.data_volume)
        self.nuvlabox_engine_version_file = "{}/.nuvlabox-engine-version".format(self.data_volume)
        self.ip_file = ".ip"
        self.ip_geolocation_file = "{}/.ipgeolocation".format(self.data_volume)
        self.vulnerabilities_file = "{}/vulnerabilities".format(self.data_volume)
        self.ca = "ca.pem"
        self.cert = "cert.pem"
        self.key = "key.pem"
        self.context = ".context"
        self.previous_net_stats_file = f"{self.data_volume}/.previous_net_stats"
        self.vpn_folder = "{}/vpn".format(self.data_volume)

        if not os.path.isdir(self.vpn_folder):
            os.makedirs(self.vpn_folder)

        self.vpn_ip_file = "{}/ip".format(self.vpn_folder)
        self.vpn_credential = "{}/vpn-credential".format(self.vpn_folder)
        self.vpn_client_conf_file = "{}/nuvlabox.conf".format(self.vpn_folder)
        self.vpn_interface_name = os.getenv('VPN_INTERFACE_NAME', 'vpn')
        self.peripherals_dir = "{}/.peripherals".format(self.data_volume)
        self.mqtt_broker_host = "data-gateway"
        self.mqtt_broker_port = 1883
        self.mqtt_broker_keep_alive = 90
        self.swarm_node_cert = f"{self.hostfs}/var/lib/docker/swarm/certificates/swarm-node.crt"
        self.nuvla_timestamp_format = "%Y-%m-%dT%H:%M:%SZ"

        if 'NUVLABOX_UUID' in os.environ and os.environ['NUVLABOX_UUID']:
            self.nuvlabox_id = os.environ['NUVLABOX_UUID']
        elif os.path.exists("{}/{}".format(self.data_volume, self.context)):
            try:
                self.nuvlabox_id = json.loads(open("{}/{}".format(self.data_volume, self.context)).read())['id']
            except json.decoder.JSONDecodeError as e:
                raise Exception(f'NUVLABOX_UUID not provided and cannot read previous context from '
                                f'{self.data_volume}/{self.context}: {str(e)}')
        else:
            # self.nuvlabox_id = get_mac_address('eth0', '')
            raise Exception(f'NUVLABOX_UUID not provided')

        if not self.nuvlabox_id.startswith("nuvlabox/"):
            self.nuvlabox_id = 'nuvlabox/{}'.format(self.nuvlabox_id)

        self.nuvlabox_engine_version = None
        if 'NUVLABOX_ENGINE_VERSION' in os.environ and os.environ['NUVLABOX_ENGINE_VERSION']:
            self.nuvlabox_engine_version = str(os.environ['NUVLABOX_ENGINE_VERSION'])

        # https://docs.nvidia.com/jetson/archives/l4t-archived/l4t-3231/index.htm
        # { driver: { board: { ic2_addrs: [addr,...], addr/device: { channel: railName}}}}
        self.nvidia_software_power_consumption_model = {
            "ina3221x": {
                "channels": 3,
                "boards": {
                    "agx_xavier": {
                        "i2c_addresses": ["1-0040", "1-0041"],
                        "channels_path": ["1-0040/iio:device0", "1-0041/iio:device1"]
                    },
                    "nano": {
                        "i2c_addresses": ["6-0040"],
                        "channels_path": ["6-0040/iio:device0"]
                    },
                    "tx1": {
                        "i2c_addresses": ["1-0040"],
                        "channels_path": ["1-0040/iio:device0"]
                    },
                    "tx1_dev_kit": {
                        "i2c_addresses": ["1-0042", "1-0043"],
                        "channels_path": ["1-0042/iio:device2", "1-0043/iio:device3"]
                    },
                    "tx2": {
                        "i2c_addresses": ["0-0040", "0-0041"],
                        "channels_path": ["0-0040/iio:device0", "0-0041/iio:device1"]
                    },
                    "tx2_dev_kit": {
                        "i2c_addresses": ["0-0042", "0-0043"],
                        "channels_path": ["0-0042/iio:device2", "0-0043/iio:device3"]
                    }
                }
            }
        }

        self.container_stats_json_file = f"{self.data_volume}/docker_stats.json"

    def api(self):
        """ Returns an Api object """

        return Api(endpoint='https://{}'.format(self.nuvla_endpoint),
                   insecure=self.nuvla_endpoint_insecure, reauthenticate=True)

    def push_event(self, data):
        """
        Push an event resource to Nuvla

        :param data: JSON payload
        :return:
        """

        try:
            self.api().add('event', data=data)
        except Exception as e:
            logging.error(f'Unable to push event to Nuvla: {data}. Reason: {str(e)}')

    @staticmethod
    def authenticate(api_instance, api_key, secret_key):
        """ Creates a user session """

        logging.info('Authenticate with "{}"'.format(api_key))
        logging.info(api_instance.login_apikey(api_key, secret_key))

        return api_instance

    @staticmethod
    def shell_execute(cmd):
        """ Shell wrapper to execute a command

        :param cmd: command to execute
        :return: all outputs
        """

        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        return {'stdout': stdout, 'stderr': stderr, 'returncode': p.returncode}

    def get_operational_status(self):
        """ Retrieves the operational status of the NuvlaBox from the .status file """

        try:
            operational_status = open("{}/{}".format(self.data_volume,
                                                     self.status_file)).readlines()[0].replace('\n', '').upper()
        except FileNotFoundError:
            logging.warning("Operational status could not be found")
            operational_status = "UNKNOWN"
        except IndexError:
            logging.warning("Operational status has not been correctly set")
            operational_status = "UNKNOWN"
            self.set_local_operational_status(operational_status)

        return operational_status

    def get_operational_status_notes(self) -> list:
        """ Retrieves the operational status notes of the NuvlaBox from the .status_notes file """

        notes = []
        try:
            notes = open(f"{self.data_volume}/{self.status_notes_file}").read().splitlines()
        except Exception as e:
            logging.warning(f"Error while reading operational status notes: {str(e)}")

        return notes

    def set_local_operational_status(self, operational_status):
        """ Write the operational status into the .status file

        :param operational_status: status of the NuvlaBox
        """

        with open("{}/{}".format(self.data_volume, self.status_file), 'w') as s:
            s.write(operational_status)

    def write_vpn_conf(self, values):
        """ Write VPN configuration into a file

        :param values: map of values for the VPN conf template
        """
        tpl = string.Template("""client

dev ${vpn_interface_name}
dev-type tun

# Certificate Configuration
# CA certificate
<ca>
${vpn_ca_certificate}
${vpn_intermediate_ca_is}
${vpn_intermediate_ca}
</ca>

# Client Certificate
<cert>
${vpn_certificate}
</cert>

# Client Key
<key>
${nuvlabox_vpn_key}
</key>

# Shared key
<tls-crypt>
${vpn_shared_key}
</tls-crypt>

remote-cert-tls server

verify-x509-name "${vpn_common_name_prefix}" name-prefix

script-security 2
up /opt/nuvlabox/scripts/get_ip.sh

auth-nocache
auth-retry nointeract

ping 60
ping-restart 120
compress lz4

${vpn_endpoints_mapped}
""")

        with open(self.vpn_client_conf_file, 'w') as vpnf:
            vpnf.write(tpl.substitute(values))

    def prepare_vpn_certificates(self):
        nuvlabox_vpn_key = f'{self.vpn_folder}/nuvlabox-vpn.key'
        nuvlabox_vpn_csr = f'{self.vpn_folder}/nuvlabox-vpn.csr'

        cmd = ['openssl', 'req', '-batch', '-nodes', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:secp521r1',
               '-keyout', nuvlabox_vpn_key, '-out', nuvlabox_vpn_csr, '-subj', f'/CN={self.nuvlabox_id.split("/")[-1]}']

        r = self.shell_execute(cmd)

        if r.get('returncode', -1) != 0:
            logging.error(f'Cannot generate certificates for VPN connection: {r.get("stdout")} | {r.get("stderr")}')
            return None, None

        try:
            wait = 0
            while not os.path.exists(nuvlabox_vpn_csr) and not os.path.exists(nuvlabox_vpn_key):
                if wait > 25:
                    # appr 5 sec
                    raise TimeoutError
                wait += 1
                time.sleep(0.2)

            with open(nuvlabox_vpn_csr) as csr:
                vpn_csr = csr.read()

            with open(nuvlabox_vpn_key) as key:
                vpn_key = key.read()
        except TimeoutError:
            logging.error(f'Unable to lookup {nuvlabox_vpn_key} and {nuvlabox_vpn_csr}')
            return None, None

        return vpn_csr, vpn_key

    def commission_vpn(self):
        """ (re)Commissions the NB via the agent API

        :return:
        """

        vpn_csr, vpn_key = self.prepare_vpn_certificates()

        if not vpn_key or not vpn_csr:
            return False

        try:
            vpn_conf_fields = requests.post("http://localhost/api/commission", json={"vpn-csr": vpn_csr}).json()
        except Exception as e:
            logging.error(f'Unable to setup VPN connection: {str(e)}')
            return False
        else:
            if not vpn_conf_fields:
                logging.error(f'Invalid response from VPN commissioning...cannot continue')
                return False

        logging.info(f'VPN configuration fields: {vpn_conf_fields}')

        vpn_values = {
            'vpn_certificate': vpn_conf_fields['vpn-certificate'],
            'vpn_intermediate_ca': vpn_conf_fields['vpn-intermediate-ca'],
            'vpn_ca_certificate': vpn_conf_fields['vpn-ca-certificate'],
            'vpn_intermediate_ca_is': vpn_conf_fields['vpn-intermediate-ca-is'],
            'vpn_shared_key': vpn_conf_fields['vpn-shared-key'],
            'vpn_common_name_prefix': vpn_conf_fields['vpn-common-name-prefix'],
            'vpn_endpoints_mapped': vpn_conf_fields['vpn-endpoints-mapped'],
            'vpn_interface_name': self.vpn_interface_name,
            'nuvlabox_vpn_key': vpn_key
        }

        self.write_vpn_conf(vpn_values)
        return True





