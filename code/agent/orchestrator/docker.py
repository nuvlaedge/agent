import base64
import logging
import os
import socket
import yaml

from subprocess import run, PIPE, TimeoutExpired

import requests
import docker
from docker import errors as docker_err
from docker.context.config import get_context_host
from docker.models.containers import Container

from agent.common import util
from agent.orchestrator import ContainerRuntimeClient, OrchestratorException


class InferIPError(Exception):
    ...


class DockerClient(ContainerRuntimeClient):
    """
    Docker client
    """

    NAME = 'docker'
    NAME_COE = 'swarm'

    def __init__(self, host_rootfs, host_home, docker_host=None,
                 check_docker_host=True):
        """
        Public constructor.

        :param host_rootfs: path to hosts' root file system
        :param host_home:
        :param docker_host: corresponds to DOCKER_HOST env var for bootstrapping
                            Docker client.
        """
        super().__init__(host_rootfs, host_home)
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.CLIENT_NAME: str = 'Docker'
        if check_docker_host:
            self.check_docker_host(docker_host)
        self.client: docker.DockerClient = \
            docker.from_env(
                environment={
                    'DOCKER_HOST': docker_host or get_context_host()})
        self.lost_quorum_hint = 'possible that too few managers are online'
        self.infra_service_endpoint_keyname = 'swarm-endpoint'
        self.join_token_manager_keyname = 'swarm-token-manager'
        self.join_token_worker_keyname = 'swarm-token-worker'
        self.data_gateway_name = "data-gateway"

        self.compute_api = 'compute-api'
        self.compute_api_port = 5000

    @classmethod
    def check_docker_host(cls, docker_socket_file):
        # FIXME: check for tcp://...
        if docker_socket_file and not os.path.exists(docker_socket_file):
            raise OrchestratorException(f'Orchestrator is "{cls.NAME}", but file '
                                        f'{docker_socket_file} is not present')


    def get_client_version(self) -> str:
        return self.client.version()['Version']

    def get_node_info(self):
        return self.client.info()

    def get_host_os(self):
        node_info = self.get_node_info()
        return f"{node_info['OperatingSystem']} {node_info['KernelVersion']}"

    def get_join_tokens(self) -> tuple:
        try:
            if self.client.swarm.attrs:
                return self.client.swarm.attrs['JoinTokens']['Manager'], \
                       self.client.swarm.attrs['JoinTokens']['Worker']
        except docker.errors.APIError as e:
            if self.lost_quorum_hint in str(e):
                # quorum is lost
                logging.warning(f'Quorum is lost. This node will no longer support '
                                f'Service and Cluster management')

        return ()

    def list_nodes(self, optional_filter: dict = None):
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
                'cluster-orchestrator': self.NAME_COE,
                'cluster-managers': managers,
                'cluster-workers': workers
            }
        else:
            return {}

    def get_api_ip_port(self):
        node_info = self.get_node_info()
        compute_api_port = os.getenv('COMPUTE_API_PORT', '5000')

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
                    raise InferIPError('Cannot infer IP')
            except (IOError, InferIPError, IndexError):
                ip = '127.0.0.1'
            else:
                # Double check - we should never get here
                if not ip:
                    logging.warning("Cannot infer the NuvlaEdge API IP!")
                    return None, compute_api_port

        return ip, compute_api_port

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
            if "node is not a swarm manager" not in str(e).lower():
                logging.debug(f"Cannot get node labels: {str(e)}")
            return []

        return self.cast_dict_to_list(node_labels)

    def is_vpn_client_running(self):
        it_vpn_container = self.client.containers.get(util.compose_project_name + "-vpn-client")
        vpn_client_running = it_vpn_container.status == 'running'
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
                logging.info(f'Job {job_id} is already running in container '
                             f'{job_container.name}')
                return True
            elif job_container.status.lower() in ['created']:
                logging.warning(f'Job {job_id} was created by not started. Removing it '
                                f'and starting a new one')
                job_container.remove()
            else:
                # then it is stopped or dead. force kill it and re-initiate
                job_container.kill()
        except AttributeError:
            # assume it is running so we don't mess anything
            return True
        except docker.errors.NotFound:
            # then it stopped by itself...maybe it ran already and just finished
            # let's not do anything just in case this is a late coming job. In the next
            # telemetry cycle, if job is there again, then we run it because this
            # container is already gone
            return True

        return False

    def launch_job(self, job_id, job_execution_id, nuvla_endpoint,
                   nuvla_endpoint_insecure=False, api_key=None, api_secret=None,
                   docker_image=None):
        # Get the compute-api network
        try:
            compute_api = self.client.containers.get(util.compose_project_name + '-compute-api')
            local_net = list(compute_api.attrs['NetworkSettings']['Networks'].keys())[0]
        except (docker.errors.NotFound, docker.errors.APIError, IndexError, KeyError,
                TimeoutError):
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
            # for some jobs (like clustering), it is better if the job container is also
            # in the default bridge network, so it doesn't get affected by network changes
            # in the NuvlaEdge
            self.client.api.connect_container_to_network(job_execution_id, 'bridge')
        except docker.errors.APIError as e:
            logging.warning(f'Could not attach {job_execution_id} to bridge network: '
                            f'{str(e)}')

    @staticmethod
    def collect_container_metrics_cpu(container_stats: dict) -> float:
        """
        Calculates the CPU consumption for a give container

        :param container_stats: Docker container statistics
        :return: CPU consumption in percentage
        """
        cs = container_stats
        cpu_percent = float('nan')

        try:
            cpu_delta = float(cs["cpu_stats"]["cpu_usage"]["total_usage"]) - \
                        float(cs["precpu_stats"]["cpu_usage"]["total_usage"])
            system_delta = float(cs["cpu_stats"]["system_cpu_usage"]) - \
                           float(cs["precpu_stats"]["system_cpu_usage"])
            online_cpus_alt = len(cs["cpu_stats"]["cpu_usage"].get("percpu_usage", []))
            online_cpus = cs["cpu_stats"].get('online_cpus', online_cpus_alt)

            if system_delta > 0.0 and online_cpus > 0:
                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0
        except (IndexError, KeyError, ValueError, ZeroDivisionError) as e:
            logging.warning('Failed to get CPU usage for container '
                            f'{cs.get("id","?")[:12]} ({cs.get("name")}): {e}')

        return cpu_percent

    @staticmethod
    def collect_container_metrics_mem(cstats: dict) -> tuple:
        """
        Calculates the Memory consumption for a give container

        :param cstats: Docker container statistics
        :return: Memory consumption tuple with percentage, usage and limit
        """
        try:
            # Get total mem usage and subtract cached memory
            if cstats["memory_stats"]["stats"].get('rss'):
                mem_usage = (float(cstats["memory_stats"]["stats"]["rss"]))/1024/1024
            else:
                mem_usage = (float(cstats["memory_stats"]["usage"]) -
                             float(cstats["memory_stats"]["stats"]["file"]))/1024/1024
            mem_limit = float(cstats["memory_stats"]["limit"]) / 1024 / 1024
            if round(mem_limit, 2) == 0.00:
                mem_percent = 0.00
            else:
                mem_percent = round(float(mem_usage / mem_limit) * 100, 2)
        except (IndexError, KeyError, ValueError, ZeroDivisionError) as e:
            mem_percent = mem_usage = mem_limit = 0.00
            logging.warning('Failed to get Memory consumption for container '
                            f'{cstats.get("id","?")[:12]} ({cstats.get("name")}): {e}')

        return mem_percent, mem_usage, mem_limit

    @staticmethod
    def collect_container_metrics_net(cstats: dict) -> tuple:
        """
        Calculates the Network consumption for a give container

        :param cstats: Docker container statistics
        :return: tuple with network bytes IN and OUT
        """
        net_in = net_out = 0.0
        try:
            if "networks" in cstats:
                net_in = sum(cstats["networks"][iface]["rx_bytes"]
                             for iface in cstats["networks"]) / 1000 / 1000
                net_out = sum(cstats["networks"][iface]["tx_bytes"]
                              for iface in cstats["networks"]) / 1000 / 1000
        except (IndexError, KeyError, ValueError) as e:
            logging.warning('Failed to get Network consumption for container '
                            f'{cstats.get("id","?")[:12]} ({cstats.get("name")}): {e}')

        return net_in, net_out

    @staticmethod
    def collect_container_metrics_block(cstats: dict) -> tuple:
        """
        Calculates the block consumption for a give container

        :param cstats: Docker container statistics
        :return: tuple with block bytes IN and OUT
        """
        blk_out = blk_in = 0.0

        io_bytes_recursive = cstats.get("blkio_stats", {}).get("io_service_bytes_recursive", [])
        if io_bytes_recursive:
            try:
                blk_in = float(io_bytes_recursive[0]["value"] / 1000 / 1000)
            except (IndexError, KeyError, TypeError) as e:
                logging.warning('Failed to get block usage (In) for container '
                                f'{cstats.get("id","?")[:12]} ({cstats.get("name")}): {e}')
            try:
                blk_out = float(io_bytes_recursive[1]["value"] / 1000 / 1000)
            except (IndexError, KeyError, TypeError):
                logging.warning('Failed to get block usage (Out) for container '
                                f'{cstats.get("id","?")[:12]} ({cstats.get("name")}): {e}')

        return blk_out, blk_in

    def list_containers(self, filters: dict = None, all: bool = False):
        """
        Bug: Sometime the Docker Python API fails to get the list of containers with the exception:
        'requests.exceptions.HTTPError: 404 Client Error: Not Found'
        This is due to docker listing containers and then inpecting them one by one.
        If in the mean time a container has been removed, it fails with the above exception.
        As a workaround, the list operation is retried if an exception occurs.
        """
        tries = 0
        max_tries = 3

        while True:
            try:
                return self.client.containers.list(filters=filters, all=all)
            except requests.exceptions.HTTPError:
                tries += 1
                logging.warning(f'Failed to list containers. Try {tries}/{max_tries}.')
                if tries >= max_tries:
                    raise

    def get_containers_stats(self, *args, **kwargs):
        containers_stats = []
        for container in self.list_containers(*args, **kwargs):
            try:
                containers_stats.append((container, container.stats(stream=False)))
            except Exception as e:
                logging.warning('Failed to get stats for container '
                                f'{container.short_id} ({container.name}): {e}')
        return containers_stats

    def collect_container_metrics(self):
        containers_metrics = []

        for container, stats in self.get_containers_stats():
            # CPU
            cpu_percent = \
                self.collect_container_metrics_cpu(stats)
            # RAM
            mem_percent, mem_usage, mem_limit = \
                self.collect_container_metrics_mem(stats)
            # NET
            net_in, net_out = \
                self.collect_container_metrics_net(stats)
            # DISK
            blk_out, blk_in = \
                self.collect_container_metrics_block(stats)

            containers_metrics.append({
                'id': container.id,
                'name': container.name,
                'container-status': container.status,
                'cpu-percent': "%.2f" % round(cpu_percent, 2),
                'mem-usage-limit': ("{}MiB / {}MiB".format(round(mem_usage, 1),
                                                           round(mem_limit, 1))),
                'mem-percent': "%.2f" % mem_percent,
                'net-in-out': "%sMB / %sMB" % (round(net_in, 1), round(net_out, 1)),
                'blk-in-out': "%sMB / %sMB" % (round(blk_in, 1), round(blk_out, 1)),
                'restart-count': (int(container.attrs["RestartCount"])
                                  if "RestartCount" in container.attrs else 0)
            })

        return containers_metrics

    def get_installation_parameters(self, search_label):
        nuvlaedge_containers = self.list_containers(filters={'label': search_label})

        try:
            myself = self.client.containers.get(socket.gethostname())
        except docker.errors.NotFound:
            logging.error(f'Cannot find this container by hostname: {socket.gethostname()}. Cannot proceed')
            raise

        config_files = myself.labels.get('com.docker.compose.project.config_files', '').split(',')
        last_update = myself.attrs.get('Created', '')
        working_dir = myself.labels.get('com.docker.compose.project.working_dir')
        project_name = myself.labels.get('com.docker.compose.project')
        environment = []
        for env_var in myself.attrs.get('Config', {}).get('Env', []):
            if env_var.split('=')[0] in self.ignore_env_variables:
                continue

            environment.append(env_var)

        nuvlaedge_containers = list(filter(lambda x: x.id != myself.id, nuvlaedge_containers))
        for container in nuvlaedge_containers:
            c_labels = container.labels
            if c_labels.get('com.docker.compose.project', '') == project_name and \
                    c_labels.get('com.docker.compose.project.working_dir', '') == working_dir:
                if container.attrs.get('Created', '') > last_update:
                    last_update = container.attrs.get('Created', '')
                    config_files = c_labels.get('com.docker.compose.project.config_files', '').split(',')
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

    def define_nuvla_infra_service(self, api_endpoint: str, tls_keys: list) -> dict:
        if not self.compute_api_is_running(self.compute_api_port):
            return {}
        return self.coe_infra_service_def(api_endpoint, tls_keys)

    def coe_infra_service_def(self, api_endpoint, tls_keys) -> dict:
        main_coe_is = self.main_coe_infra_service(api_endpoint, tls_keys)
        other_coe_is = self.other_coe_infra_service(api_endpoint)
        return {**other_coe_is, **main_coe_is}

    @staticmethod
    def main_coe_infra_service(api_endpoint: str, tls_keys: list) -> dict:
        infra_service = {}
        if api_endpoint:
            infra_service["swarm-endpoint"] = api_endpoint
            if tls_keys:
                infra_service["swarm-client-ca"] = tls_keys[0]
                infra_service["swarm-client-cert"] = tls_keys[1]
                infra_service["swarm-client-key"] = tls_keys[2]
        return infra_service

    def other_coe_infra_service(self, api_endpoint):
        try:
            infra_service = self.infer_if_additional_coe_exists(
                fallback_address=api_endpoint.replace('https://', '').split(':')[0])
        except Exception as ex:
            self.logger.warning('Failed discovering additional COE: %s', ex)
            infra_service = {}
        return infra_service

    def get_partial_decommission_attributes(self) -> list:
        return ['swarm-token-manager',
                'swarm-token-worker',
                'swarm-client-key',
                'swarm-client-ca',
                'swarm-client-cert',
                'swarm-endpoint']

    def is_k3s_running(self, k3s_address: str) -> dict:
        """
        Checks specifically if k3s is installed

        :param k3s_address: endpoint address for the kubernetes API
        :return: commissioning-ready kubernetes infra
        """
        if not k3s_address:
            return {}

        k3s_conf = f'{self.hostfs}/etc/rancher/k3s/k3s.yaml'
        if not os.path.isfile(k3s_conf):
            return {}
        with open(k3s_conf) as kubeconfig:
            try:
                k3s = yaml.safe_load(kubeconfig)
            except yaml.YAMLError:
                return {}

        k3s_port = k3s['clusters'][0]['cluster']['server'].split(':')[-1]
        k3s_cluster_info = dict()
        k3s_cluster_info['kubernetes-endpoint'] = f'https://{k3s_address}:{k3s_port}'
        try:
            ca = k3s["clusters"][0]["cluster"]["certificate-authority-data"]
            cert = k3s["users"][0]["user"]["client-certificate-data"]
            key = k3s["users"][0]["user"]["client-key-data"]
            k3s_cluster_info['kubernetes-client-ca'] = base64.b64decode(ca).decode()
            k3s_cluster_info['kubernetes-client-cert'] = base64.b64decode(cert).decode()
            k3s_cluster_info['kubernetes-client-key'] = base64.b64decode(key).decode()
        except Exception as e:
            logging.warning(f'Unable to lookup k3s certificates: {str(e)}')
            return {}

        return k3s_cluster_info

    def infer_if_additional_coe_exists(self, fallback_address=None) -> dict:
        # Check if there is a k8s installation available as well
        k8s_apiserver_process = 'kube-apiserver'
        k8s_cluster_info = {}

        cmd = f'grep -R "{k8s_apiserver_process}" {self.hostfs}/proc/*/comm'

        try:
            result = run(cmd, stdout=PIPE, stderr=PIPE, timeout=5,
                         encoding='UTF-8', shell=True).stdout
        except TimeoutExpired as e:
            logging.warning(f'Could not infer if Kubernetes is also installed on '
                            f'the host: {str(e)}')
            return k8s_cluster_info

        if not result:
            # try k3s
            try:
                return self.is_k3s_running(fallback_address)
            except:
                return k8s_cluster_info

        process_args_file = result.split(':')[0].rstrip('comm') + 'cmdline'
        try:
            with open(process_args_file) as pid_file_cmdline:
                k8s_apiserver_args = pid_file_cmdline.read()
        except FileNotFoundError:
            return k8s_cluster_info

        # cope with weird characters
        k8s_apiserver_args = k8s_apiserver_args.replace('\x00', '\n').splitlines()
        args_list = list(map(lambda x: x.lstrip('--'), k8s_apiserver_args[1:]))

        # convert list to dict
        try:
            args = { args_list[i].split('=')[0]: args_list[i].split('=')[-1] for i in range(0, len(args_list)) }
        except IndexError:
            # should never get into this exception, but keep it anyway, just to be safe
            logging.warning(f'Unable to infer k8s cluster info from apiserver arguments {args_list}')
            return k8s_cluster_info

        arg_address = "advertise-address"
        arg_port = "secure-port"
        arg_ca = "client-ca-file"
        arg_cert = "kubelet-client-certificate"
        arg_key = "kubelet-client-key"

        try:
            k8s_endpoint = f'https://{args[arg_address]}:{args[arg_port]}' \
                if not args[arg_address].startswith("http") else f'{args[arg_address]}:{args[arg_port]}'

            with open(f'{self.hostfs}{args[arg_ca]}') as ca:
                k8s_client_ca = ca.read()

            with open(f'{self.hostfs}{args[arg_cert]}') as cert:
                k8s_client_cert = cert.read()

            with open(f'{self.hostfs}{args[arg_key]}') as key:
                k8s_client_key = key.read()

            k8s_cluster_info.update({
                'kubernetes-endpoint': k8s_endpoint,
                'kubernetes-client-ca': k8s_client_ca,
                'kubernetes-client-cert': k8s_client_cert,
                'kubernetes-client-key': k8s_client_key
            })
        except (KeyError, FileNotFoundError) as e:
            logging.warning(f'Cannot destructure or access certificates from k8s apiserver arguments {args}. {str(e)}')
            return {}

        return k8s_cluster_info

    def get_all_nuvlaedge_components(self) -> list:
        nuvlaedge_containers = self.list_containers(filters={'label': 'nuvlaedge.component=True'},
                                                    all=True)

        return list(map(lambda y: y.name, nuvlaedge_containers))

    def container_run_command(self, image, name, command: str = None,
                              args: str = None,
                              network: str = None, remove: bool = True,
                              **kwargs) -> str:
        if not command:
            command = args
        try:
            output: bytes = self.client.containers.run(
                image,
                command=command,
                name=name,
                remove=remove,
                network=network)
            return output.decode('utf-8')
        except (docker_err.ImageNotFound,
                docker_err.ContainerError,
                docker_err.APIError) as ex:
            self.logger.error("Failed running container '%s' from '%s': %s",
                              name, image, ex.explanation)

    def container_remove(self, name: str, **kwargs):
        try:
            cont: Container = self.client.containers.get(name)
            if cont.status == 'running':
                cont.stop()
            cont.remove()
        except docker_err.NotFound:
            pass
        except Exception as ex:
            self.logger.warning('Failed removing %s container.', exc_info=ex)

    def compute_api_is_running(self, container_api_port) -> bool:
        """
        Pokes at the compute-api endpoint to see if it is up and running

        Only valid for Docker installations

        :return: True or False
        """

        if not container_api_port:
            container_api_port = self.compute_api_port

        compute_api_url = f'https://{self.compute_api}:{container_api_port}'

        try:
            if self.client.containers.get(self.compute_api).status \
                    != 'running':
                return False

            requests.get(compute_api_url, timeout=3)
        except requests.exceptions.SSLError:
            # this is expected. It means it is up, we just weren't authorized
            pass
        except (docker_err.NotFound, docker_err.APIError, TimeoutError):
            return False
        except requests.exceptions.ConnectionError:
            # Can happen if the Compute API takes longer than normal on start
            self.logger.info('Too many requests... Compute API not ready yet')
            return False

        return True
