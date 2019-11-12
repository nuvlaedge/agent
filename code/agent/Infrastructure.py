#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Infrastructure

It takes care of updating the NuvlaBox infrastructure services
and respective credentials in Nuvla
"""

import logging
import docker
import json
from agent.common import nuvlabox as nb
from agent.Telemetry import Telemetry


class Infrastructure(object):
    """ The Infrastructure class includes all methods and
    properties necessary update the infrastructure services
    and respective credentials in Nuvla, whenever the local
    configurations change

    """

    def __init__(self, data_volume, api=None):
        """ Constructs an Infrastructure object, with a status placeholder

        :param data_volume: shared volume
        :param nuvlabox_id: UUID of the nuvlabox resource
        :param api: api object"""

        self.data_volume = data_volume
        self.swarm_manager_token_file = "swarm-manager-token"
        self.swarm_worker_token_file = "swarm-worker-token"
        self.commissioning_file = ".commission"
        self.ip_file = ".ip"
        self.api = nb.ss_api() if not api else api
        self.ca = "ca.pem"
        self.cert = "cert.pem"
        self.key = "key.pem"
        self.telemetry_instance = Telemetry(data_volume, None)

    @staticmethod
    def get_swarm_tokens():
        """ Retrieve Swarm tokens """

        return docker.from_env().swarm.attrs['JoinTokens']['Manager'], docker.from_env().swarm.attrs['JoinTokens']['Worker']

    @staticmethod
    def write_file(file, content, is_json=False):
        """ Static method to write to file

        :param file: full path to file
        :param content: content of the file
        :param is_json: tells if the content is to be processed as JSON
        """

        if is_json:
            content = json.dumps(content)

        with open(file, 'w') as f:
            f.write(content)

    def token_diff(self, current_manager_token, current_worker_token):
        """ Checks if the Swarm tokens have changed

        :param current_manager_token: current swarm manager token
        :param current_worker_token: current swarm worker token
        :return true or false
        """

        manager_token_file = "{}/{}".format(self.data_volume, self.swarm_manager_token_file)
        worker_token_file = "{}/{}".format(self.data_volume, self.swarm_worker_token_file)

        try:
            open(worker_token_file).readlines()[0].replace('\n', '')
            open(manager_token_file).readlines()[0].replace('\n', '')
        except (FileNotFoundError, IndexError):
            logging.info("Docker Swarm tokens not registered yet...registering")
            self.write_file(manager_token_file, current_manager_token)
            self.write_file(worker_token_file, current_worker_token)
            return True

        return False

    def get_tls_keys(self):
        """ Finds and returns the Docker API client TLS keys """

        ca_file = "{}/{}".format(self.data_volume, self.ca)
        cert_file = "{}/{}".format(self.data_volume, self.cert)
        key_file = "{}/{}".format(self.data_volume, self.key)

        try:
            swarm_client_ca = open(ca_file).read()
            swarm_client_cert = open(cert_file).read()
            swarm_client_key = open(key_file).read()
        except (FileNotFoundError, IndexError):
            logging.warning("Docker API TLS key have not been set yet! Please check the NuvlaBox compute-api status")
            return None

        return swarm_client_ca, swarm_client_cert, swarm_client_key

    def has_ip_changed(self, ip):
        """ Compare the current IP with the one previously registered

        :param ip: current device IP
        :return bool
        """

        try:
            with open("{}/{}".format(self.data_volume, self.ip_file)) as i:
                if ip == i.read():
                    return False
        except FileNotFoundError:
            logging.info("Registering the device IP for the first time")

        self.write_file("{}/{}".format(self.data_volume, self.ip_file), ip)
        return True

    def do_commission(self, payload):
        """ Perform the operation """

        try:
            self.api._cimi_post(nb.NUVLABOX_RESOURCE_ID+"/commission", json=payload)
        except:
            raise

        self.write_file("{}/{}".format(self.data_volume, self.commissioning_file), payload, is_json=True)

    def needs_commission(self, current_conf):
        """ Check whether the current commission data structure
        has changed wrt to the previous one

        :param current_conf: current commissioning data
        :return bool
        """

        try:
            with open("{}/{}".format(self.data_volume, self.commissioning_file)) as r:
                if current_conf == json.loads(r.read()):
                    return False
                else:
                    return True
        except FileNotFoundError:
            logging.info("Commissioning the NuvlaBox for the first time...")
            return True

    def try_commission(self):
        """ Checks whether any of the system configurations have changed
        and if so, returns True or False """

        commission_payload = {}
        swarm_tokens = self.get_swarm_tokens()
        self.token_diff(swarm_tokens[0], swarm_tokens[1])
        commission_payload['swarm-token-manager'] = swarm_tokens[0]
        commission_payload['swarm-token-worker'] = swarm_tokens[1]

        tls_keys = self.get_tls_keys()
        if tls_keys:
            commission_payload["swarm-client-ca"] = tls_keys[0]
            commission_payload["swarm-client-cert"] = tls_keys[1]
            commission_payload["swarm-client-key"] = tls_keys[2]

        my_ip = self.telemetry_instance.get_ip()
        commission_payload["swarm-endpoint"] = "https://{}:5000".format(my_ip)

        ## TODO: check VPN CSR

        if self.needs_commission(commission_payload):
            logging.info("Commissioning the NuvlaBox...{}".format(commission_payload))
            self.do_commission(commission_payload)
