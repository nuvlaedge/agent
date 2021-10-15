#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Infrastructure

It takes care of updating the NuvlaBox infrastructure services
and respective credentials in Nuvla
"""

import logging
import docker
import json
import requests
import time
from agent.common import NuvlaBoxCommon
from agent.Telemetry import Telemetry
from datetime import datetime
from os import path, stat, remove
from threading import Thread


class Infrastructure(NuvlaBoxCommon.NuvlaBoxCommon, Thread):
    """ The Infrastructure class includes all methods and
    properties necessary update the infrastructure services
    and respective credentials in Nuvla, whenever the local
    configurations change

    """

    def __init__(self, data_volume, refresh_period=15):
        """ Constructs an Infrastructure object, with a status placeholder

        :param data_volume: shared volume
        """

        NuvlaBoxCommon.NuvlaBoxCommon.__init__(self, shared_data_volume=data_volume)
        Thread.__init__(self, daemon=True)
        self.telemetry_instance = Telemetry(data_volume, None, enable_container_monitoring=False)
        self.compute_api = 'compute-api'
        self.compute_api_port = '5000'
        self.ssh_flag = f"{data_volume}/.ssh"
        self.refresh_period = refresh_period

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

    def swarm_token_diff(self, current_manager_token, current_worker_token):
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
        """ Finds and returns the Container orchestration API client TLS keys """

        ca_file = "{}/{}".format(self.data_volume, self.ca)
        cert_file = "{}/{}".format(self.data_volume, self.cert)
        key_file = "{}/{}".format(self.data_volume, self.key)

        try:
            client_ca = open(ca_file).read()
            client_cert = open(cert_file).read()
            client_key = open(key_file).read()
        except (FileNotFoundError, IndexError):
            logging.warning("Container orchestration API TLS keys have not been set yet!")
            return None

        return client_ca, client_cert, client_key

    def do_commission(self, payload):
        """ Perform the operation

        :param payload: commissioning payload
        :return
        """
        if not payload:
            logging.warning("Tried commissioning with empty payload. Nothing to do.")
            return

        logging.info("Commissioning the NuvlaBox...{}".format(payload))
        try:
            self.api()._cimi_post(self.nuvlabox_id+"/commission", json=payload)
        except Exception as e:
            logging.error("Could not commission with payload {}: {}".format(payload, e))
            return False

        if "vpn-csr" in payload:
            # get the respective VPN credential that was just created
            with open("{}/{}".format(self.data_volume, self.context)) as vsi:
                vpn_server_id = json.loads(vsi.read()).get("vpn-server-id")

            searcher_filter = self.build_vpn_credential_search_filter(vpn_server_id)

            attempts = 0
            credential_id = None
            while attempts <= 20:
                logging.info("Getting VPN credential from Nuvla...")
                try:
                    credential_id = self.api().search("credential", filter=searcher_filter, last=1).resources[0].id
                    break
                except IndexError:
                    logging.exception("Cannot find VPN credential in Nuvla after commissioning")
                    time.sleep(2)
                except Exception as e:
                    logging.info("something %s" % e)

                attempts += 1

            if not credential_id:
                logging.warning("Failing to provide necessary values for NuvlaBox VPN client")
                return None

            vpn_credential = self.api()._cimi_get(credential_id)
            # save_vpn_credential
            vpn_server = self.api()._cimi_get(vpn_server_id)

            vpn_conf_endpoints = ''
            for connection in vpn_server["vpn-endpoints"]:
                vpn_conf_endpoints += "\n<connection>\nremote {} {} {}\n</connection>\n".format(
                    connection["endpoint"],
                    connection["port"],
                    connection["protocol"]
                )

            vpn_fields = {
                "vpn-intermediate-ca": "\n".join(vpn_credential["vpn-intermediate-ca"]),
                "vpn-certificate": vpn_credential["vpn-certificate"],
                "vpn-ca-certificate": vpn_server["vpn-ca-certificate"],
                "vpn-intermediate-ca-is": "\n".join(vpn_server["vpn-intermediate-ca"]),
                "vpn-shared-key": vpn_server["vpn-shared-key"],
                "vpn-common-name-prefix": vpn_server["vpn-common-name-prefix"],
                "vpn-endpoints-mapped": vpn_conf_endpoints
            }

            return vpn_fields

        return True

    def needs_commission(self, current_conf):
        """ Check whether the current commission data structure
        has changed wrt to the previous one

        :param current_conf: current commissioning data
        :return commissioning payload
        """

        try:
            with open("{}/{}".format(self.data_volume, self.commissioning_file)) as r:
                old_conf = json.loads(r.read())
                if current_conf == old_conf:
                    return {}
                else:
                    diff_conf = {}
                    for key, value in current_conf.items():
                        if key in old_conf:
                            if old_conf[key] == value:
                                continue

                        diff_conf[key] = value

                    return diff_conf
        except FileNotFoundError:
            logging.info("Auto-commissioning the NuvlaBox for the first time...")
            return current_conf

    def get_nuvlabox_capabilities(self, commissioning_dict: dict):
        """ Finds the NuvlaBox capabilities and adds them to the NB commissioning payload

        :param commissioning_dict: the commission payload, as a dict, to be changed in case there are capabilities
        :return:
        """

        # NUVLA_JOB_PULL if job-engine-lite has been deployed with the NBE
        commissioning_dict['capabilities'] = []
        if self.container_runtime.has_pull_job_capability():
            commissioning_dict['capabilities'].append('NUVLA_JOB_PULL')

    def compute_api_is_running(self, container_api_port) -> bool:
        """
        Pokes ate the compute-api endpoint to see if it is up and running

        Only valid for Docker installations

        :return: True or False
        """

        if NuvlaBoxCommon.ORCHESTRATOR in ['docker', 'swarm']:
            return False

        if not container_api_port:
            container_api_port = self.compute_api_port

        compute_api_url = f'https://{self.compute_api}:{container_api_port}'

        try:
            if self.container_runtime.client.containers.get(self.compute_api).status != 'running':
                return False

            requests.get(compute_api_url, timeout=3)
        except requests.exceptions.SSLError:
            # this is expected. It means it is up, we just weren't authorized
            pass
        except Exception as e:
            return False

        return True

    def get_node_role_from_status(self) -> str or None:
        """
        Look up the local nuvlabox-status file and take the cluster-node-role value from there

        :return: node role
        """

        try:
            with open(self.nuvlabox_status_file) as ns:
                role = json.load(ns).get('cluster-node-role')
        except FileNotFoundError:
            role = None

        return role

    def read_commissioning_file(self) -> dict:
        """
        Reads the current content of the commissioning file from the local shared volume

        :return: last commissioning content
        """
        try:
            with open("{}/{}".format(self.data_volume, self.commissioning_file)) as r:
                commission_payload = json.loads(r.read())
        except FileNotFoundError:
            commission_payload = {}

        return commission_payload

    def needs_cluster_commission(self) -> dict:
        """
        Checks if the commissioning needs to carry cluster information

        :return: commission-ready cluster info
        """

        cluster_info = self.container_runtime.get_cluster_info(default_cluster_name=f'cluster_{self.nuvlabox_id}')

        node_info = self.container_runtime.get_node_info()
        cluster_id = self.container_runtime.get_cluster_id(node_info)
        node_id = self.container_runtime.get_node_id(node_info)

        # we only commission the cluster when the NuvlaBox status
        # has already been updated with its "node-id"
        with open(self.nuvlabox_status_file) as nbs:
            nuvlabox_status = json.load(nbs)

        if not cluster_info:
            # it is not a manager but...
            if cluster_id and node_id and node_id == nuvlabox_status.get('node-id'):
                # it is a worker, and NB status is aware of that, so we can update the cluster with it
                return {
                    "cluster-id": cluster_id,
                    "cluster-node-id": node_id,
                }
            else:
                return {}

        if nuvlabox_status.get('node-id') in cluster_info.get('cluster-managers', []) and \
                node_id == nuvlabox_status.get('node-id'):
            return cluster_info

        return {}

    def get_compute_endpoint(self, vpn_ip: str) -> tuple:
        """
        Find the endpoint and port of the compute API

        :returns tuple (api_endpoint, port)
        """
        container_api_ip, container_api_port = self.container_runtime.get_api_ip_port()

        api_endpoint = None
        if vpn_ip:
            api_endpoint = f"https://{vpn_ip}:{container_api_port}"
        elif container_api_ip and container_api_port:
            api_endpoint = f"https://{container_api_ip}:{container_api_port}"

        return api_endpoint, container_api_port

    def try_commission(self):
        """ Checks whether any of the system configurations have changed
        and if so, returns True or False """
        cluster_join_tokens = self.container_runtime.get_join_tokens()
        cluster_info = self.needs_cluster_commission()

        # initialize the commissioning payload
        commission_payload = cluster_info
        minimum_commission_payload = cluster_info
        old_commission_payload = self.read_commissioning_file()

        my_vpn_ip = self.telemetry_instance.get_vpn_ip()
        api_endpoint, container_api_port = self.get_compute_endpoint(my_vpn_ip)

        commission_payload["tags"] = self.container_runtime.get_node_labels()
        if sorted(commission_payload.get('tags', [])) != sorted(old_commission_payload.get('tags', [])):
            minimum_commission_payload['tags'] = commission_payload.get('tags', [])

        tls_keys = self.get_tls_keys()
        infra_service = self.container_runtime.define_nuvla_infra_service(api_endpoint, tls_keys)
        # 1st time commissioning the IS, so we need to also pass the keys, even if they haven't changed
        if infra_service and \
                not old_commission_payload.get(self.container_runtime.infra_service_endpoint_keyname) and \
                (self.compute_api_is_running(container_api_port) or NuvlaBoxCommon.ORCHESTRATOR == 'kubernetes'):
            minimum_commission_payload.update(infra_service)
        else:
            for k, v in infra_service.items():
                if v != old_commission_payload.get(k):
                    minimum_commission_payload[k] = v

        commission_payload.update(infra_service)

        # if this node is a worker, them we must force remove some assets
        node_role = self.get_node_role_from_status()
        if node_role and node_role.lower() == 'worker':
            minimum_commission_payload['removed'] = commission_payload['removed'] = \
                self.container_runtime.get_partial_decommission_attributes()

        # atm, it isn't clear whether these will make sense for k8s
        # if they do, then this block should be moved to an abstractmethod of the ContainerRuntime
        if cluster_join_tokens and len(cluster_join_tokens) > 1 and NuvlaBoxCommon.ORCHESTRATOR in ['docker', 'swarm']:
            self.swarm_token_diff(cluster_join_tokens[0], cluster_join_tokens[1])
            commission_payload.update({
                'swarm-token-manager': cluster_join_tokens[0],
                'swarm-token-worker': cluster_join_tokens[1]
            })

        if commission_payload.get('swarm-token-manager') != old_commission_payload.get('swarm-token-manager'):
            minimum_commission_payload['swarm-token-manager'] = cluster_join_tokens[0]
        if commission_payload.get('swarm-token-worker') != old_commission_payload.get('swarm-token-worker'):
            minimum_commission_payload['swarm-token-worker'] = cluster_join_tokens[1]

        self.get_nuvlabox_capabilities(commission_payload)
        if sorted(commission_payload.get('capabilities', [])) != sorted(old_commission_payload.get('capabilities', [])) \
                or any(k in minimum_commission_payload for k in infra_service):
            minimum_commission_payload['capabilities'] = commission_payload.get('capabilities', [])

        # remove the keys from the commission payload, to avoid confusion on the server side
        for attr in minimum_commission_payload['removed']:
            try:
                commission_payload.pop(attr)
                minimum_commission_payload.pop(attr)
            except KeyError:
                pass

        if self.do_commission(minimum_commission_payload):
            self.write_file("{}/{}".format(self.data_volume, self.commissioning_file),
                            commission_payload,
                            is_json=True)

    def build_vpn_credential_search_filter(self, vpn_server_id):
        """ Simply build the API query for searching this NuvlaBox's VPN credential

        :param vpn_server_id: ID of the VPN server
        :return str
        """

        return 'method="create-credential-vpn-nuvlabox" and vpn-common-name="{}" and parent="{}"'.format(
            self.nuvlabox_id,
            vpn_server_id
        )

    def watch_vpn_credential(self, vpn_is_id=None):
        """ Watches the VPN credential in Nuvla for changes

        :param vpn_is_id: VPN server ID
        """

        if not vpn_is_id:
            return None

        search_filter = self.build_vpn_credential_search_filter(vpn_is_id)
        logging.info("Watching VPN credential in Nuvla...")
        try:
            credential_id = self.api().search("credential", filter=search_filter, last=1).resources[0].id
            logging.info("Found VPN credential ID %s" % credential_id)
        except IndexError:
            credential_id = None

        if not credential_id:
            # If cannot find a VPN credential in Nuvla, then it is either in the process of being created
            # or it has been removed from Nuvla
            logging.info("VPN server is set but cannot find VPN credential in Nuvla. Commissioning VPN...")

            if path.exists(self.vpn_credential) and stat(self.vpn_credential).st_size != 0:
                logging.warning("NOTE: VPN credential exists locally, so it was removed from Nuvla")

            self.commission_vpn()
        else:
            vpn_credential_nuvla = self.api()._cimi_get(credential_id)

            # IF there is a VPN credential in Nuvla:
            #  - if we also have one locally, BUT is different, then recommission
            if path.exists(self.vpn_credential) and stat(self.vpn_credential).st_size != 0 and path.exists(self.vpn_client_conf_file):
                with open(self.vpn_credential) as vpn_local:
                    local_vpn_credential = json.loads(vpn_local.read())

                if vpn_credential_nuvla['updated'] != local_vpn_credential['updated']:
                    logging.warning("VPN credential has been modified in Nuvla at {}. Recommissioning"
                                    .format(vpn_credential_nuvla['updated']))
                    # Recommission
                    self.commission_vpn()
                    remove(self.vpn_credential)
                    return None
                    # else, do nothing cause nothing has changed
            else:
                # - IF we don't have it locally, but there's one in Nuvla, then:
                #     - IF the vpn-client is already running, then all is good, just save the VPN credential locally
                logging.warning("VPN credential exists in Nuvla, but not locally")

                try:
                    vpn_client_running = self.container_runtime.is_vpn_client_running()
                except docker.errors.NotFound as e:
                    vpn_client_running = False
                    logging.info("VPN client is not running")

                if vpn_client_running and self.telemetry_instance.get_vpn_ip():
                    # just save a copy of the VPN credential locally
                    self.write_file(self.vpn_credential, vpn_credential_nuvla, is_json=True)
                    logging.info("VPN client is now running. Saving VPN credential locally at {}"
                                    .format(self.vpn_credential))
                else:
                    # there is a VPN credential in Nuvla, but not locally, and the VPN client is not running
                    # maybe something went wrong, just recommission
                    logging.warning("The local VPN client is either not running or missing its configuration. Forcing VPN recommissioning...")
                    self.commission_vpn()

    def set_immutable_ssh_key(self):
        """
        Takes a public SSH key from env and adds it to the installing host user.
        This is only done once, at installation time.

        :return:
        """

        if path.exists(self.ssh_flag):
            logging.debug("Immutable SSH key has already been processed at installation time")
            with open(self.ssh_flag) as sshf:
                original_ssh_key = sshf.read()
                if self.ssh_pub_key != original_ssh_key:
                    logging.warning(f'Received new SSH key but the original {original_ssh_key} is immutable. Ignoring')
            return

        event = {
            "category": "action",
            "content": {
                "resource": {
                    "href": self.nuvlabox_id
                },
                "state": f"Unknown problem while setting immutable SSH key"
            },
            "severity": "high",
            "timestamp": datetime.utcnow().strftime(self.nuvla_timestamp_format)
        }
        if self.ssh_pub_key and self.installation_home:
            ssh_folder = f"{self.hostfs}{self.installation_home}/.ssh"
            if not path.exists(ssh_folder):
                event['content']['state'] = f"Cannot set immutable SSH key because {ssh_folder} does not exist"

                self.push_event(event)
                return

            with open(f'{self.data_volume}/{self.context}') as nb:
                nb_owner = json.load(nb).get('owner')

            event_owners = [nb_owner, self.nuvlabox_id] if nb_owner else [self.nuvlabox_id]
            event['acl'] = {'owners': event_owners}

            logging.info(f'Setting immutable SSH key {self.ssh_pub_key} for {self.installation_home}')
            try:
                with NuvlaBoxCommon.timeout(10):
                    if not self.container_runtime.install_ssh_key(self.ssh_pub_key, ssh_folder):
                        return
            except Exception as e:
                msg = f'An error occurred while setting immutable SSH key: {str(e)}'
                logging.error(msg)
                event['content']['state'] = msg
                self.push_event(event)

            with open(self.ssh_flag, 'w') as sshfw:
                sshfw.write(self.ssh_pub_key)

    def run(self):
        """
        Threads the commissioning cycles, so that they don't interfere with the main telemetry cycle
        """
        while True:
            self.try_commission()
            time.sleep(self.refresh_period)
