# -*- coding: utf-8 -*-

""" NuvlaBox Common

List of common attributes for all classes
"""

import json
import logging
import os
import socket
import requests
import signal
import string
import time

from contextlib import contextmanager
from subprocess import PIPE, Popen, run
from nuvla.api import Api

from agent.orchestrator import ContainerRuntimeClient
from agent.orchestrator.docker import DockerClient
from agent.orchestrator.kubernetes import KubernetesClient

KUBERNETES_SERVICE_HOST = os.getenv('KUBERNETES_SERVICE_HOST')
if KUBERNETES_SERVICE_HOST:
    from kubernetes import client, config
    ORCHESTRATOR = 'kubernetes'
    ORCHESTRATOR_COE = ORCHESTRATOR
else:
    import docker
    ORCHESTRATOR = 'docker'
    ORCHESTRATOR_COE = 'swarm'


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
        raise
    finally:
        # Unregister the signal so it won't be triggered
        # if the timeout is not reached.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)


class OrchestratorException(Exception):
    ...


# --------------------
class NuvlaBoxCommon:
    """ Common set of methods and variables for the NuvlaBox agent
    """

    def __init__(self, shared_data_volume="/srv/nuvlabox/shared"):
        """ Constructs an Infrastructure object, with a status placeholder

        :param shared_data_volume: shared volume target path
        """
        self.logger: logging.Logger = logging.getLogger(__name__)

        self.data_volume = shared_data_volume
        self.docker_socket_file = '/var/run/docker.sock'
        self.hostfs = "/rootfs"
        self.ssh_pub_key = os.environ.get('NUVLABOX_IMMUTABLE_SSH_PUB_KEY')
        self.host_user_home_file = f'{self.data_volume}/.host_user_home'
        self.installation_home = self.set_installation_home(self.host_user_home_file)
        self.nuvla_endpoint_key = 'NUVLA_ENDPOINT'
        self.nuvla_endpoint_insecure_key = 'NUVLA_ENDPOINT_INSECURE'
        self.nuvlabox_nuvla_configuration = f'{self.data_volume}/.nuvla-configuration'
        self.nuvla_endpoint, self.nuvla_endpoint_insecure = self.set_nuvla_endpoint()
        # Also store the Nuvla connection details for future restarts
        conf = f"{self.nuvla_endpoint_key}={self.nuvla_endpoint}\n{self.nuvla_endpoint_insecure_key}={str(self.nuvla_endpoint_insecure)}"
        self.save_nuvla_configuration(self.nuvlabox_nuvla_configuration, conf)

        self.container_runtime = self.set_runtime_client_details()
        self.mqtt_broker_host = self.container_runtime.data_gateway_name
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
        self.vpn_config_extra = self.set_vpn_config_extra()
        self.peripherals_dir = "{}/.peripherals".format(self.data_volume)
        self.mqtt_broker_port = 1883
        self.mqtt_broker_keep_alive = 90
        self.swarm_node_cert = f"{self.hostfs}/var/lib/docker/swarm/certificates/swarm-node.crt"
        self.nuvla_timestamp_format = "%Y-%m-%dT%H:%M:%SZ"
        self.nuvlabox_id = self.set_nuvlabox_id()
        nbe_version = os.getenv('NUVLABOX_ENGINE_VERSION')
        self.nuvlabox_engine_version = str(nbe_version) if nbe_version else None

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

    def set_vpn_config_extra(self) -> str:
        """
        If env var VPN_CONFIG_EXTRA is set, update vpn configuration.
        If not set, use the saved value from the shared volume.

        :return: extra config as a string
        """
        extra_config_file = f'{self.vpn_folder}/.extra_config'

        extra_config = os.getenv('VPN_CONFIG_EXTRA')
        if extra_config is not None:
            extra_config = extra_config.replace(r'\n', '\n')
            try:
                with open(extra_config_file, 'w') as f:
                    f.write(extra_config)
            except OSError:
                self.logger.exception('Failed to write VPN extra config file')
            return extra_config

        try:
            with open(extra_config_file) as f:
                return f.read()
        except FileNotFoundError:
            pass
        except OSError:
            self.logger.exception('Failed to read VPN extra config file')

        return ''

    @staticmethod
    def set_installation_home(host_user_home_file: str) -> str:
        """
        Finds the path for the HOME dir used during installation

        :param host_user_home_file: location of the file where the previous installation home value was saved
        :return: installation home path
        """
        if os.path.exists(host_user_home_file):
            with open(host_user_home_file) as userhome:
                return userhome.read().strip()
        else:
            return os.environ.get('HOST_HOME')

    def set_nuvla_endpoint(self) -> tuple:
        """
        Defines the Nuvla endpoint based on the environment

        :return: clean Nuvla endpoint and whether it is insecure or not -> (str, bool)
        """
        nuvla_endpoint_raw = os.environ["NUVLA_ENDPOINT"] if "NUVLA_ENDPOINT" in os.environ else "nuvla.io"
        nuvla_endpoint_insecure_raw = os.environ["NUVLA_ENDPOINT_INSECURE"] if "NUVLA_ENDPOINT_INSECURE" in os.environ else False
        try:
            with open(self.nuvlabox_nuvla_configuration) as nuvla_conf:
                local_nuvla_conf = nuvla_conf.read().split()

            nuvla_endpoint_line = list(filter(lambda x: x.startswith(self.nuvla_endpoint_key), local_nuvla_conf))
            if nuvla_endpoint_line:
                nuvla_endpoint_raw = nuvla_endpoint_line[0].split('=')[-1]

            nuvla_endpoint_insecure_line = list(filter(lambda x: x.startswith(self.nuvla_endpoint_insecure_key),
                                                       local_nuvla_conf))
            if nuvla_endpoint_insecure_line:
                nuvla_endpoint_insecure_raw = nuvla_endpoint_insecure_line[0].split('=')[-1]
        except FileNotFoundError:
            self.logger.debug('Local Nuvla configuration does not exist yet - first time running the NuvlaBox Engine...')
        except IndexError as e:
            self.logger.debug(f'Unable to read Nuvla configuration from {self.nuvlabox_nuvla_configuration}: {str(e)}')

        while nuvla_endpoint_raw[-1] == "/":
            nuvla_endpoint_raw = nuvla_endpoint_raw[:-1]

        if isinstance(nuvla_endpoint_insecure_raw, str):
            if nuvla_endpoint_insecure_raw.lower() == "false":
                nuvla_endpoint_insecure_raw = False
            else:
                nuvla_endpoint_insecure_raw = True
        else:
            nuvla_endpoint_insecure_raw = bool(nuvla_endpoint_insecure_raw)

        return nuvla_endpoint_raw.replace("https://", ""), nuvla_endpoint_insecure_raw

    @staticmethod
    def save_nuvla_configuration(file_path, content):
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(content)

    def set_runtime_client_details(self) -> ContainerRuntimeClient:
        """
        Sets the right container runtime client based on the underlying orchestrator, and
        sets the Data Gateway name
        :return: instance of a ContainerRuntimeClient
        """
        if ORCHESTRATOR == 'kubernetes':
            return KubernetesClient(self.hostfs, self.installation_home)
        else:
            if os.path.exists(self.docker_socket_file):
                return DockerClient(self.hostfs, self.installation_home)
            else:
                raise OrchestratorException(f'Orchestrator is "{ORCHESTRATOR}", but file '
                                            f'{self.docker_socket_file} is not present')

    def set_nuvlabox_id(self) -> str:
        """
        Discovers the NuvlaBox ID either from env or from a previous run

        :return: clean nuvlabox ID as a str
        """
        new_nuvlabox_id = os.getenv('NUVLABOX_UUID')

        if os.path.exists("{}/{}".format(self.data_volume, self.context)):
            try:
                nuvlabox_id = json.loads(open("{}/{}".format(self.data_volume, self.context)).read())['id']
                if new_nuvlabox_id and new_nuvlabox_id.split('/')[-1] != nuvlabox_id.split('/')[-1]:
                    raise RuntimeError(f'You are trying to install a new NuvlaBox {new_nuvlabox_id} even though a '
                                       f'previous NuvlaBox installation ({nuvlabox_id}) still exists in the system! '
                                       f'You can either delete the previous installation (removing all data volumes) or '
                                       f'fix the NUVLABOX_UUID environment variable to match the old {nuvlabox_id}')
            except json.decoder.JSONDecodeError as e:
                raise Exception(f'NUVLABOX_UUID not provided and cannot read previous context from '
                                f'{self.data_volume}/{self.context}: {str(e)}')
        elif new_nuvlabox_id:
            nuvlabox_id = new_nuvlabox_id
        else:
            raise Exception(f'NUVLABOX_UUID not provided')

        if not nuvlabox_id.startswith("nuvlabox/"):
            nuvlabox_id = 'nuvlabox/{}'.format(nuvlabox_id)

        return nuvlabox_id

    @staticmethod
    def get_api_keys():
        nuvlabox_api_key = os.environ.get("NUVLABOX_API_KEY")
        nuvlabox_api_secret = os.environ.get("NUVLABOX_API_SECRET")
        if nuvlabox_api_key:
            del os.environ["NUVLABOX_API_KEY"]
        if nuvlabox_api_secret:
            del os.environ["NUVLABOX_API_SECRET"]

        return nuvlabox_api_key, nuvlabox_api_secret

    def api(self):
        """ Returns an Api object """

        return Api(endpoint='https://{}'.format(self.nuvla_endpoint),
                   insecure=self.nuvla_endpoint_insecure, reauthenticate=True, compress=True)

    def push_event(self, data):
        """
        Push an event resource to Nuvla

        :param data: JSON payload
        :return:
        """

        try:
            self.api().add('event', data)
        except Exception as e:
            self.logger.error(f'Unable to push event to Nuvla: {data}. Reason: {str(e)}')

    def authenticate(self, api_instance, api_key, secret_key):
        """ Creates a user session """

        self.logger.info('Authenticate with "{}"'.format(api_key))
        self.logger.info(api_instance.login_apikey(api_key, secret_key))

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

    def write_json_to_file(self, file_path: str, content: dict, mode: str = 'w') -> bool:
        """
        Write JSON content into a file

        :param file_path: path of the file to be written
        :param content: JSON content
        :param mode: mode in which to open the file for writing
        :return: True if file was written with success. False otherwise
        """
        try:
            with open(file_path, mode) as f:
                f.write(json.dumps(content))
        except Exception as e:
            self.logger.exception(f'Exception in write_json_to_file: {e}')
            return False

        return True

    @staticmethod
    def read_json_file(file_path: str) -> dict:
        """
        Reads a JSON file. Error should be caught by the calling module

        :param file_path: path of the file to be read
        :return: content of the file, as a dict
        """
        with open(file_path) as f:
            return json.load(f)

    def get_nuvlabox_version(self) -> int:
        """
        Gives back this NuvlaBox Engine's version

        :return: major version of the NuvlaBox Engine, as an integer
        """
        if self.nuvlabox_engine_version:
            version = int(self.nuvlabox_engine_version.split('.')[0])
        elif os.path.exists("{}/{}".format(self.data_volume, self.context)):
            version = self.read_json_file(f"{self.data_volume}/{self.context}")['version']
        else:
            version = 2

        return version

    def get_operational_status(self):
        """ Retrieves the operational status of the NuvlaBox from the .status file """

        try:
            operational_status = open("{}/{}".format(self.data_volume,
                                                     self.status_file)).readlines()[0].replace('\n', '').upper()
        except FileNotFoundError:
            self.logger.warning("Operational status could not be found")
            operational_status = "UNKNOWN"
        except IndexError:
            self.logger.warning("Operational status has not been correctly set")
            operational_status = "UNKNOWN"
            self.set_local_operational_status(operational_status)

        return operational_status

    def get_operational_status_notes(self) -> list:
        """
        Retrieves the operational status notes of the NuvlaBox from the .status_notes
        file
        """

        notes = []
        try:
            notes = open(f"{self.data_volume}/{self.status_notes_file}").\
                read().splitlines()
        except Exception as e:
            self.logger.warning(f"Error while reading operational status notes: {str(e)}")

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

${vpn_extra_config}
""")

        with open(self.vpn_client_conf_file, 'w') as vpnf:
            vpnf.write(tpl.substitute(values))

    def prepare_vpn_certificates(self):
        nuvlabox_vpn_key = f'{self.vpn_folder}/nuvlabox-vpn.key'
        nuvlabox_vpn_csr = f'{self.vpn_folder}/nuvlabox-vpn.csr'

        cmd = ['openssl', 'req', '-batch', '-nodes', '-newkey', 'ec', '-pkeyopt',
               'ec_paramgen_curve:secp521r1', '-keyout', nuvlabox_vpn_key, '-out',
               nuvlabox_vpn_csr, '-subj', f'/CN={self.nuvlabox_id.split("/")[-1]}']

        r = self.shell_execute(cmd)

        if r.get('returncode', -1) != 0:
            self.logger.error(f'Cannot generate certificates for VPN connection: '
                              f'{r.get("stdout")} | {r.get("stderr")}')
            return None, None

        try:
            wait = 0
            while not os.path.exists(nuvlabox_vpn_csr) and \
                    not os.path.exists(nuvlabox_vpn_key):
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
            self.logger.error(f'Unable to lookup {nuvlabox_vpn_key} and '
                              f'{nuvlabox_vpn_csr}')
            return None, None

        return vpn_csr, vpn_key

    def commission_vpn(self):
        """ (re)Commissions the NB via the agent API

        :return:
        """
        self.logger.info(f'Starting VPN commissioning...')

        vpn_csr, vpn_key = self.prepare_vpn_certificates()

        if not vpn_key or not vpn_csr:
            return False

        try:
            vpn_conf_fields: requests.Response = \
                requests.post(
                    "http://localhost/api/commission",
                    json={"vpn-csr": vpn_csr})

            vpn_conf_fields = vpn_conf_fields.json()

        except Exception as e:

            self.logger.error(f'Unable to setup VPN connection: {str(e)}')
            return False

        if not vpn_conf_fields:
            self.logger.error(f'Invalid response from VPN commissioning... '
                              f'cannot continue')
            return False

        self.logger.info(f'VPN configuration fields: {vpn_conf_fields}')

        vpn_values = {
            'vpn_certificate': vpn_conf_fields['vpn-certificate'],
            'vpn_intermediate_ca': vpn_conf_fields['vpn-intermediate-ca'],
            'vpn_ca_certificate': vpn_conf_fields['vpn-ca-certificate'],
            'vpn_intermediate_ca_is': vpn_conf_fields['vpn-intermediate-ca-is'],
            'vpn_shared_key': vpn_conf_fields['vpn-shared-key'],
            'vpn_common_name_prefix': vpn_conf_fields['vpn-common-name-prefix'],
            'vpn_endpoints_mapped': vpn_conf_fields['vpn-endpoints-mapped'],
            'vpn_interface_name': self.vpn_interface_name,
            'nuvlabox_vpn_key': vpn_key,
            'vpn_extra_config': self.vpn_config_extra
        }

        self.write_vpn_conf(vpn_values)
        return True
