"""
Orchestration base class. To be extended and implemented by docker or kubernetes
"""
import os
from abc import ABC, abstractmethod
from agent.common import util


KUBERNETES_SERVICE_HOST = os.getenv('KUBERNETES_SERVICE_HOST')
if KUBERNETES_SERVICE_HOST:
    ORCHESTRATOR = 'kubernetes'
    ORCHESTRATOR_COE = ORCHESTRATOR
else:
    ORCHESTRATOR = 'docker'
    ORCHESTRATOR_COE = 'swarm'


class ContainerRuntimeClient(ABC):
    """
    Base abstract class for the Docker and Kubernetes clients
    """
    CLIENT_NAME: str

    def __init__(self, host_rootfs, host_home):
        self.client = None
        self.hostfs = host_rootfs
        self.job_engine_lite_component = util.compose_project_name + "-job-engine-lite"
        self.job_engine_lite_image = None
        self.vpn_client_component = util.compose_project_name + '-vpn-client'
        self.host_home = host_home
        self.ignore_env_variables = ['NUVLAEDGE_API_KEY', 'NUVLAEDGE_API_SECRET']
        self.data_gateway_name = None

    @abstractmethod
    def get_node_info(self):
        """
        Get high level info about the hosting node
        """

    @abstractmethod
    def get_host_os(self):
        """
        Get operating system of the hosting node
        """

    @abstractmethod
    def get_join_tokens(self) -> tuple:
        """
        Get token for joining this node
        """

    @abstractmethod
    def list_nodes(self, optional_filter={}):
        """
        List all the nodes in the cluster
        """

    @abstractmethod
    def get_cluster_info(self, default_cluster_name=None):
        """
        Get information about the cluster
        """

    @abstractmethod
    def get_api_ip_port(self):
        """
        Get the full API endpoint
        """

    @abstractmethod
    def has_pull_job_capability(self):
        """
        Checks if NuvlaEdge supports pull mode for jobs
        """

    @abstractmethod
    def get_node_labels(self):
        """
        Collects the labels from the hosting node
        """

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

    @abstractmethod
    def install_ssh_key(self, ssh_pub_key, ssh_folder):
        """
        Takes an SSH public key and adds it to the host's HOME authorized keys
        (aka ssh_folder)
        """

    @abstractmethod
    def is_nuvla_job_running(self, job_id, job_execution_id):
        """
        Finds if a job is still running
        :param job_id: nuvla ID of the job
        :param job_execution_id: container ID of the job
        """

    @abstractmethod
    def launch_job(self, job_id, job_execution_id, nuvla_endpoint,
                   nuvla_endpoint_insecure=False, api_key=None,
                   api_secret=None, docker_image=None):
        """
        Launches a new job
        :param job_id: nuvla ID of the job
        :param job_execution_id: name of the container/pod
        :param nuvla_endpoint: Nuvla endpoint
        :param nuvla_endpoint_insecure: whether to use TLS or not
        :param api_key: API key credential for the job to access Nuvla
        :param api_secret: secret for the api_key
        :param docker_image: docker image name
        """

    @abstractmethod
    def collect_container_metrics(self):
        """
        Scans all visible containers and reports their resource consumption
        :return:
        """

    @abstractmethod
    def get_installation_parameters(self, search_label):
        """
        Scans all the NuvlaEdge components and returns all parameters that are relevant to
         the installation of the NB
        :param search_label: label to be used for searching the components
        """

    @abstractmethod
    def read_system_issues(self, node_info):
        """
        Checks if the underlying container management system is reporting any errors or
         warnings
        :param node_info: the result of self.get_node_info()
        """

    @abstractmethod
    def get_node_id(self, node_info):
        """
        Retrieves the node ID
        :param node_info: the result of self.get_node_info()
        """

    @abstractmethod
    def get_cluster_id(self, node_info, default_cluster_name=None):
        """
        Gets the cluster ID
        :param node_info: the result of self.get_node_info()
        :param default_cluster_name: default cluster name in case an ID is not found
        """

    @abstractmethod
    def get_cluster_managers(self):
        """
        Retrieves the cluster manager nodes
        """

    @abstractmethod
    def get_host_architecture(self, node_info):
        """
        Retrieves the host system arch
        :param node_info: the result of self.get_node_info()
        """

    @abstractmethod
    def get_hostname(self, node_info=None):
        """
        Retrieves the hostname
        :param node_info: the result of self.get_node_info()
        """

    @abstractmethod
    def get_cluster_join_address(self, node_id):
        """
        Retrieved the IP address of a manager that can be joined for clustering actions
        :param node_id: ID of the node
        """

    @abstractmethod
    def is_node_active(self, node):
        """
        Checks if a cluster node is ready/active
        :param node: Node object, from self.list_nodes()
        """

    @abstractmethod
    def get_container_plugins(self):
        """
        Lists the container plugins installed in the system
        """

    @abstractmethod
    def define_nuvla_infra_service(self, api_endpoint: str, tls_keys: list) -> dict:
        """
        Defines the infra service structure for commissioning

        :param api_endpoint: endpoint of the Docker/K8s API
        :param tls_keys: TLS keys for authenticating with the API endpoint (ca, crt, key)

        :returns dict of the infra service for commissioning
        """

    @abstractmethod
    def get_partial_decommission_attributes(self) -> list:
        """
        Says which attributes to partially decommission in case the node is a worker

        :returns list of attributes
        """

    @abstractmethod
    def infer_if_additional_coe_exists(self, fallback_address: str = None) -> dict:
        """
        Tries to discover if there is another COE running in the host,
        that can be used for deploying apps from Nuvla

        @param fallback_address: fallback IP/FQDN of the NuvlaEdge's infrastructure service
         in case we cannot find one for the additional COE

        @returns COE attributes as a dict, as expected by the Nuvla commissioning:
                 [coe]-endpoint, [coe]-client-ca, [coe]-client-cert and [coe]-client-key
        """

    @abstractmethod
    def get_all_nuvlaedge_components(self) -> list:
        """
        Finds the names of all NuvlaEdge components installed on the edge device

        :return: list of components' names
        """

    @abstractmethod
    def get_client_version(self) -> str:
        """
        Retrieves the version of the operational orchestrator

        :returns version of the orchestrator in string
        """
