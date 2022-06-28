import base64
import json
import logging
import os

import socket
import yaml

from subprocess import run, PIPE, TimeoutExpired

from agent.orchestrator import ContainerRuntimeClient, ORCHESTRATOR_COE
import docker


class InferIPError(Exception):
    ...


class DockerClient(ContainerRuntimeClient):
    """
    Docker client
    """

    def __init__(self, host_rootfs, host_home):
        super().__init__(host_rootfs, host_home)
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.CLIENT_NAME: str = 'Docker'
        self.client = docker.from_env()
        self.lost_quorum_hint = 'possible that too few managers are online'
        self.infra_service_endpoint_keyname = 'swarm-endpoint'
        self.join_token_manager_keyname = 'swarm-token-manager'
        self.join_token_worker_keyname = 'swarm-token-worker'
        self.data_gateway_name = "data-gateway"

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
                    raise InferIPError('Cannot infer IP')
            except (IOError, InferIPError, IndexError):
                ip = '127.0.0.1'
            else:
                # Double check - we should never get here
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
            if "node is not a swarm manager" not in str(e).lower():
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
            compute_api = self.client.containers.get('compute-api')
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
            # in the NuvlaBox
            self.client.api.connect_container_to_network(job_execution_id, 'bridge')
        except docker.errors.APIError as e:
            logging.warning(f'Could not attach {job_execution_id} to bridge network: '
                            f'{str(e)}')

    @staticmethod
    def collect_container_metrics_cpu(cstats: dict, old_cpu_total: float,
                                      old_cpu_system: float,
                                      errors: list = None) -> float:
        """
        Calculates the CPU consumption for a give container

        :param cstats: Docker container statistics
        :param old_cpu_total: previous total CPU usage
        :param old_cpu_system: previous system CPU usage
        :param errors: ongoing list of collection errors to append to if needed
        :return: CPU consumption in percentage
        """
        try:
            cpu_total = float(cstats["cpu_stats"]["cpu_usage"]["total_usage"])
            cpu_system = float(cstats["cpu_stats"]["system_cpu_usage"])

            online_cpus = cstats["cpu_stats"] \
                .get("online_cpus",
                     len(cstats["cpu_stats"]["cpu_usage"].get("percpu_usage", [])))

            cpu_delta = cpu_total - old_cpu_total
            system_delta = cpu_system - old_cpu_system

            cpu_percent = 0.0
            if system_delta > 0.0 and online_cpus > 0:
                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0
        except (IndexError, KeyError, ValueError, ZeroDivisionError):
            errors.append("CPU")
            cpu_percent = 0.0

        return cpu_percent

    @staticmethod
    def collect_container_metrics_mem(cstats: dict, errors: list) -> tuple:
        """
        Calculates the Memory consumption for a give container

        :param cstats: Docker container statistics
        :param errors: ongoing list of collection errors to append to if needed
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
        except (IndexError, KeyError, ValueError):
            errors.append("Mem")
            mem_percent = mem_usage = mem_limit = 0.00

        return mem_percent, mem_usage, mem_limit

    @staticmethod
    def collect_container_metrics_net(cstats: dict) -> tuple:
        """
        Calculates the Network consumption for a give container

        :param cstats: Docker container statistics
        :return: tuple with network bytes IN and OUT
        """
        net_in = net_out = 0.0
        if "networks" in cstats:
            net_in = sum(cstats["networks"][iface]["rx_bytes"]
                         for iface in cstats["networks"]) / 1000 / 1000
            net_out = sum(cstats["networks"][iface]["tx_bytes"]
                          for iface in cstats["networks"]) / 1000 / 1000

        return net_in, net_out

    @staticmethod
    def collect_container_metrics_block(cstats: dict, errors: list) -> tuple:
        """
        Calculates the block consumption for a give container

        :param cstats: Docker container statistics
        :param errors: ongoing list of collection errors to append to if needed
        :return: tuple with block bytes IN and OUT
        """
        io_bytes_recursive = cstats.get("blkio_stats", {}).get("io_service_bytes_recursive", [])
        if io_bytes_recursive:
            try:
                blk_in = float(io_bytes_recursive[0]["value"] / 1000 / 1000)
            except (IndexError, KeyError, TypeError):
                errors.append("blk_in")
                blk_in = 0.0

            try:
                blk_out = float(io_bytes_recursive[1]["value"] / 1000 / 1000)
            except (IndexError, KeyError, TypeError):
                errors.append("blk_out")
                blk_out = 0.0
        else:
            blk_out = blk_in = 0.0

        return blk_out, blk_in

    def collect_container_metrics(self):

        docker_stats = []

        all_containers = self.client.containers.list()
        for container in all_containers:
            docker_stats.append(self.client.api.stats(container.id))

        # get first samples (needed for cpu monitoring)
        old_cpu = []

        for c_stat in docker_stats:
            try:
                container_stats = json.loads(next(c_stat))
            except docker.errors.NotFound:
                logging.warning(f'Docker container id {c_stat} not found')
                old_cpu.append(None)
                continue

            try:
                old_cpu.append(
                    (float(container_stats["cpu_stats"]["cpu_usage"]["total_usage"]),
                     float(container_stats["cpu_stats"]["system_cpu_usage"])))
            except KeyError:
                old_cpu.append((0.0, 0.0))

        # now the actual monitoring
        out = []
        for i, c_stat in enumerate(docker_stats):
            if not old_cpu:
                logging.warning(f'Container {all_containers[i]} '
                                f'info not available, skipping this iteration')
                continue
            container = all_containers[i]
            try:
                container_stats = json.loads(next(c_stat))
            except StopIteration:
                logging.warning(f'Container {c_stat} stats iteration finished, return')
                continue
            except docker.errors.NotFound:
                logging.warning(f'Docker container id {c_stat} not found')
                continue
            collection_errors = []

            #
            # -----------------
            # CPU
            cpu_percent = \
                self.collect_container_metrics_cpu(container_stats, old_cpu[i][0],
                                                   old_cpu[i][1], collection_errors)
            #
            # -----------------
            # MEM
            mem_percent, mem_usage, mem_limit = \
                self.collect_container_metrics_mem(container_stats, collection_errors)
            #
            # -----------------
            # NET
            net_in, net_out = self.collect_container_metrics_net(container_stats)
            #
            # -----------------
            # BLOCK
            blk_out, blk_in = \
                self.collect_container_metrics_block(container_stats, collection_errors)

            if collection_errors:
                logging.info(f"Cannot get {','.join(collection_errors)} "
                             f"stats for container {container.name}")

            # -----------------
            out.append({
                'id': container.id,
                'name': container.name,
                'container-status': container.status,
                'cpu-percent': "%.2f" % round(cpu_percent, 2),
                'mem-usage-limit': ("{}MiB / {}GiB".format(round(mem_usage, 2),
                                                           round(mem_limit / 1024, 2))),
                'mem-percent': "%.2f" % mem_percent,
                'net-in-out': "%sMB / %sMB" % (round(net_in, 2), round(net_out, 2)),
                'blk-in-out': "%sMB / %sMB" % (round(blk_in, 2), round(blk_out, 2)),
                'restart-count': (int(container.attrs["RestartCount"])
                                  if "RestartCount" in container.attrs else 0)
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
        last_update = myself.attrs.get('Created', '')
        working_dir = myself.labels.get('com.docker.compose.project.working_dir')
        project_name = myself.labels.get('com.docker.compose.project')
        environment = []
        for env_var in myself.attrs.get('Config', {}).get('Env', []):
            if env_var.split('=')[0] in self.ignore_env_variables:
                continue

            environment.append(env_var)

        nuvlabox_containers = list(filter(lambda x: x.id != myself.id, nuvlabox_containers))
        for container in nuvlabox_containers:
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
        try:
            infra_service = self.infer_if_additional_coe_exists(
                fallback_address=api_endpoint.replace('https://', '').split(':')[0])
        except (IndexError, ConnectionError):
            # this is a non-critical step, so we should never fail because of it
            infra_service = {}
        if api_endpoint:
            infra_service["swarm-endpoint"] = api_endpoint

            if tls_keys:
                infra_service["swarm-client-ca"] = tls_keys[0]
                infra_service["swarm-client-cert"] = tls_keys[1]
                infra_service["swarm-client-key"] = tls_keys[2]

            return infra_service

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
        k3s_cluster_info = {}
        k3s_conf = f'{self.hostfs}/etc/rancher/k3s/k3s.yaml'
        if not os.path.isfile(k3s_conf) or not k3s_address:
            return k3s_cluster_info

        with open(k3s_conf) as kubeconfig:
            try:
                k3s = yaml.safe_load(kubeconfig)
            except yaml.YAMLError:
                return k3s_cluster_info

        k3s_port = k3s['clusters'][0]['cluster']['server'].split(':')[-1]
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

    def get_all_nuvlabox_components(self) -> list:
        nuvlabox_containers = self.client.containers.list(filters={'label': 'nuvlabox.component=True'},
                                                          all=True)

        return list(map(lambda y: y.name, nuvlabox_containers))
