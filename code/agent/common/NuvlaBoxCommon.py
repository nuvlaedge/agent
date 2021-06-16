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
from contextlib import contextmanager
from nuvla.api import Api
from subprocess import PIPE, Popen

KUBERNETES_SERVICE_HOST = os.getenv('KUBERNETES_SERVICE_HOST')
if KUBERNETES_SERVICE_HOST:
    from kubernetes import client, config
    ORCHESTRATOR = 'kubernetes'
else:

    import docker
    ORCHESTRATOR = 'docker'


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


class NuvlaBoxCommon():
    """ Common set of methods and variables for the NuvlaBox agent
    """
    def __init__(self, shared_data_volume="/srv/nuvlabox/shared"):
        """ Constructs an Infrastructure object, with a status placeholder

        :param shared_data_volume: shared volume target path
        """

        self.docker_socket_file = '/var/run/docker.sock'

        if ORCHESTRATOR == 'kubernetes':
            config.load_incluster_config()
            self.container_client = client.CoreV1Api()
        else:
            if os.path.exists(self.docker_socket_file):
                self.container_client = docker.from_env()
            else:
                raise Exception(f'Orchestrator is "{ORCHESTRATOR}", but file {self.docker_socket_file} is not present')

        self.data_volume = shared_data_volume
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
        self.nuvlabox_nuvla_configuration = f'{self.data_volume}/.nuvla-configuration'
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
        self.hostfs = "/rootfs"
        self.swarm_node_cert = f"{self.hostfs}/var/lib/docker/swarm/certificates/swarm-node.crt"
        self.nuvla_timestamp_format = "%Y-%m-%dT%H:%M:%SZ"
        self.job_engine_lite_image = None
        self.lost_quorum_hint = 'possible that too few managers are online'

        nuvla_endpoint_raw = None
        nuvla_endpoint_insecure_raw = None
        self.nuvla_endpoint_key = 'NUVLA_ENDPOINT'
        self.nuvla_endpoint_insecure_key = 'NUVLA_ENDPOINT_INSECURE'
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

        self.docker_stats_json_file = f"{self.data_volume}/docker_stats.json"

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
            with timeout(5):
                while not os.path.exists(nuvlabox_vpn_csr) and not os.path.exists(nuvlabox_vpn_key):
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





