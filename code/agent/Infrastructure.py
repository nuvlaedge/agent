#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Infrastructure

It takes care of updating the NuvlaBox infrastructure services
and respective credentials in Nuvla
"""

import logging
import docker
from agent.common import nuvlabox as nb


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
        self.swarm_manager_token_file = ".swarm-manager-token"
        self.swarm_worker_token_file = ".swarm-worker-token"
        self.api = nb.ss_api() if not api else api
        self.ca = "ca.pem"
        self.cert = "cert.pem"
        self.key = "key.pem"

    @staticmethod
    def get_swarm_tokens():
        """ Retrieve Swarm tokens """

        return docker.from_env().swarm.attrs['JoinTokens']['Manager'], docker.from_env().swarm.attrs['JoinTokens']['Worker']

    @staticmethod
    def write_file(file, content):
        """ Static method to write to file

        :param file: full path to file
        :param content: content of the file """

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

    def do_recommission(self, payload):
        """ Perform the operation """

        self.api._cimi_post(nb.NUVLABOX_ID+"/recommission", json=payload)

    def try_recommission(self):
        """ Checks whether any of the system configurations have changed
        and if so, returns True or False """

        recommission_payload = {}
        swarm_tokens = self.get_swarm_tokens()
        if self.token_diff(swarm_tokens[0], swarm_tokens[1]):
            recommission_payload['swarm-token-manager'] = swarm_tokens[0]
            recommission_payload['swarm-token-worker'] = swarm_tokens[1]

        tls_keys = self.get_tls_keys()
        if tls_keys:
            recommission_payload["swarm-client-ca"] = tls_keys[0]
            recommission_payload["swarm-client-cert"] = tls_keys[1]
            recommission_payload["swarm-client-key"] = tls_keys[2]

        if recommission_payload:
            logging.info("Recommissioning the NuvlaBox...")
            self.do_recommission(recommission_payload)
