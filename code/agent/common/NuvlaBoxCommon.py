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
import docker
from nuvla.api import Api
from subprocess import PIPE, Popen


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


def logger(log_level, log_file):
    """ Configures logging """

    logging.basicConfig(filename=log_file)

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
    parser.add_argument('-l', '--log-filepath', dest='log_file', default=None, metavar='FILE')

    return parser


class NuvlaBoxCommon():
    """ Common set of methods and variables for the NuvlaBox agent
    """
    def __init__(self, shared_data_volume="/srv/nuvlabox/shared"):
        """ Constructs an Infrastructure object, with a status placeholder

        :param shared_data_volume: shared Docker volume target path
        """
        self.docker_client = docker.from_env()
        self.data_volume = shared_data_volume
        self.activation_flag = "{}/.activated".format(self.data_volume)
        self.swarm_manager_token_file = "swarm-manager-token"
        self.swarm_worker_token_file = "swarm-worker-token"
        self.commissioning_file = ".commission"
        self.status_file = ".status"
        self.ip_file = ".ip"
        self.ca = "ca.pem"
        self.cert = "cert.pem"
        self.key = "key.pem"
        self.context = ".context"
        self.vpn_folder = "{}/vpn".format(self.data_volume)
        self.vpn_ip_file = "{}/ip".format(self.vpn_folder)
        self.vpn_infra_file = "{}/vpn-is".format(self.vpn_folder)
        self.vpn_credential = "{}/vpn-credential".format(self.vpn_folder)
        self.vpn_client_conf_file = "{}/nuvlabox.conf".format(self.vpn_folder)
        self.mqtt_broker_host = "nb-mosquitto"
        self.mqtt_broker_port = 1883
        self.mqtt_broker_keep_alive = 90

        nuvla_endpoint_raw = os.environ["NUVLA_ENDPOINT"] if "NUVLA_ENDPOINT" in os.environ else "nuvla.io"
        while nuvla_endpoint_raw[-1] == "/":
            nuvla_endpoint_raw = nuvla_endpoint_raw[:-1]

        self.nuvla_endpoint = nuvla_endpoint_raw.replace("https://", "")

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
            self.nuvlabox_id = json.loads(open("{}/{}".format(self.data_volume, self.context)).read())['id']
        else:
            self.nuvlabox_id = get_mac_address('eth0', '')

        if not self.nuvlabox_id.startswith("nuvlabox/"):
            self.nuvlabox_id = 'nuvlabox/{}'.format(self.nuvlabox_id)

    def api(self):
        """ Returns an Api object """

        return Api(endpoint='https://{}'.format(self.nuvla_endpoint),
                   insecure=self.nuvla_endpoint_insecure, reauthenticate=True)

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

    def set_local_operational_status(self, operational_status):
        """ Write the operational status into the .status file

        :param operational_status: status of the NuvlaBox
        """

        with open("{}/{}".format(self.data_volume, self.status_file), 'w') as s:
            s.write(operational_status)



