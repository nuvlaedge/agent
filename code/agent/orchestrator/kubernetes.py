import logging
import os

from kubernetes import client, config

from agent.orchestrator import ContainerRuntimeClient, ORCHESTRATOR_COE


class KubernetesClient(ContainerRuntimeClient):
    """
    Kubernetes client
    """

    def __init__(self, host_rootfs, host_home):
        super().__init__(host_rootfs, host_home)
        self.CLIENT_NAME: str = 'Kubernetes'
        config.load_incluster_config()
        self.client = client.CoreV1Api()
        self.client_apps = client.AppsV1Api()
        self.namespace = os.getenv('MY_NAMESPACE', 'nuvlaedge')
        self.job_engine_lite_image = os.getenv('NUVLAEDGE_JOB_ENGINE_LITE_IMAGE')
        self.host_node_ip = os.getenv('MY_HOST_NODE_IP')
        self.host_node_name = os.getenv('MY_HOST_NODE_NAME')
        self.vpn_client_component = os.getenv('NUVLAEDGE_VPN_COMPONENT_NAME', 'vpn-client')
        self.infra_service_endpoint_keyname = 'kubernetes-endpoint'
        self.join_token_manager_keyname = 'kubernetes-token-manager'
        self.join_token_worker_keyname = 'kubernetes-token-worker'
        self.data_gateway_name = f"data-gateway.{self.namespace}"

    def get_node_info(self):
        if self.host_node_name:
            this_node = self.client.read_node(self.host_node_name)
            try:
                return this_node
            except AttributeError:
                logging.warning(f'Cannot infer node information for node "{self.host_node_name}"')

        return None

    def get_host_os(self):
        node = self.get_node_info()
        if node:
            return f"{node.status.node_info.os_image} {node.status.node_info.kernel_version}"

        return None

    def get_join_tokens(self) -> tuple:
        # NOTE: I don't think we can get the cluster join token from the API
        # it needs to come from the cluster mgmt tool (i.e. k0s, k3s, kubeadm, etc.)
        return ()

    def list_nodes(self, optional_filter={}):
        return self.client.list_node().items

    def get_cluster_info(self, default_cluster_name=None):
        node_info = self.get_node_info()

        cluster_id = self.get_cluster_id(node_info, default_cluster_name)

        nodes = self.list_nodes()
        managers = []
        workers = []
        for n in nodes:
            workers.append(n.metadata.name)
            for label in n.metadata.labels:
                if 'node-role' in label and 'master' in label:
                    workers.pop()
                    managers.append(n.metadata.name)
                    break

        return {
            'cluster-id': cluster_id,
            'cluster-orchestrator': ORCHESTRATOR_COE,
            'cluster-managers': managers,
            'cluster-workers': workers
        }

    def get_api_ip_port(self):
        all_endpoints = self.client.list_endpoints_for_all_namespaces().items

        ip_port = None
        if self.host_node_ip:
            return self.host_node_ip, 6443

        try:
            endpoint = list(filter(lambda x: x.metadata.name.lower() == 'kubernetes', all_endpoints))[0]
        except IndexError:
            logging.error('There are no "kubernetes" endpoints where to get the API IP and port from')
            return None, None

        for subset in endpoint.subsets:
            for addr in subset.addresses:
                if addr.ip:
                    self.host_node_ip = addr.ip
                    break

            for port in subset.ports:
                if f'{port.name}/{port.protocol}' == 'https/TCP':
                    ip_port = port.port
                    break

            if self.host_node_ip and ip_port:
                return self.host_node_ip, ip_port

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
        name = 'nuvlaedge-ssh-installer'
        try:
            existing_pod = self.client.read_namespaced_pod(namespace=self.namespace, name=name)
        except client.exceptions.ApiException as e:
            if e.status != 404: # If 404, this is good, we can proceed
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
        nuvlaedge_deployments = self.client_apps.list_namespaced_deployment(namespace=self.namespace,
                                                                            label_selector=search_label).items

        environment = []
        for dep in nuvlaedge_deployments:
            dep_containers = dep.spec.template.spec.containers
            for container in dep_containers:
                try:
                    env = container.env if container.env else []
                    for env_var in env:
                        try:
                            _ = env_var.value_from
                            # this is a templated var. No need to report it
                            continue
                        except AttributeError:
                            pass

                        environment.append(f'{env_var.name}={env_var.value}')
                except AttributeError:
                    pass

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

    def get_client_version(self):
        # IMPORTANT: this is only implemented for this k8s client class
        return self.get_node_info().status.node_info.kubelet_version

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

    def define_nuvla_infra_service(self, api_endpoint: str, tls_keys: list) -> dict:
        if api_endpoint:
            infra_service = {
                "kubernetes-endpoint": api_endpoint
            }

            if tls_keys:
                infra_service["kubernetes-client-ca"] = tls_keys[0]
                infra_service["kubernetes-client-cert"] = tls_keys[1]
                infra_service["kubernetes-client-key"] = tls_keys[2]

            return infra_service
        else:
            return {}

    def get_partial_decommission_attributes(self) -> list:
        # TODO for k8s
        return []

    def infer_if_additional_coe_exists(self, fallback_address: str=None) -> dict:
        # For k8s installations, we might want to see if there's also Docker running alongside
        # TODO
        return {}

    def get_all_nuvlaedge_components(self) -> list:
        # TODO
        return []

    def get_current_container_id(self) -> str:
        # TODO
        return ''
