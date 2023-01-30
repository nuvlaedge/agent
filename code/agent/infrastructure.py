#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaEdge Infrastructure

It takes care of updating the NuvlaEdge infrastructure services
and respective credentials in Nuvla
"""
import os
import logging
import docker
import docker.errors as docker_err
import json
import requests
import time
from agent.common import NuvlaEdgeCommon, util
from agent.telemetry import Telemetry
from datetime import datetime
from os import path, stat, remove
from threading import Thread


class Infrastructure(NuvlaEdgeCommon.NuvlaEdgeCommon, Thread):
    """ The Infrastructure class includes all methods and
    properties necessary update the infrastructure services
    and respective credentials in Nuvla, whenever the local
    configurations change
    """

    def __init__(self, data_volume, telemetry: Telemetry = None, refresh_period=15):
        """ Constructs an Infrastructure object, with a status placeholder

        :param data_volume: shared volume
        """
        super(Infrastructure, self).__init__(shared_data_volume=data_volume)
        Thread.__init__(self, daemon=True)

        self.infra_logger: logging.Logger = logging.getLogger(__name__)

        if telemetry:
            self.telemetry_instance = telemetry
        else:
            self.telemetry_instance = Telemetry(data_volume, None)
        self.compute_api = os.getenv('COMPOSE_PROJECT') + '-compute-api-1'
        self.compute_api_port = os.getenv('COMPUTE_API_PORT')
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

        util.atomic_write(file, content)

    def swarm_token_diff(self, current_manager_token, current_worker_token):
        """ Checks if the Swarm tokens have changed

        :param current_manager_token: current swarm manager token
        :param current_worker_token: current swarm worker token
        :return true or false
        """

        manager_token_file = f"{self.data_volume}/{self.swarm_manager_token_file}"
        worker_token_file = f"{self.data_volume}/{self.swarm_worker_token_file}"

        try:
            open(worker_token_file).readlines()[0].replace('\n', '')
            open(manager_token_file).readlines()[0].replace('\n', '')
        except (FileNotFoundError, IndexError):
            self.infra_logger.info("Docker Swarm tokens not registered yet...registering")
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
            self.infra_logger.warning("Container orchestration API TLS keys have not been"
                                      " set yet!")
            return None

        return client_ca, client_cert, client_key

    def do_commission(self, payload):
        """ Perform the operation

        :param payload: commissioning payload
        :return
        """

        if not payload:
            self.infra_logger.debug("Tried commissioning with empty payload. Nothing "
                                    "to do")
            return None

        self.infra_logger.info("Commissioning the NuvlaEdge...{}".format(payload))
        try:
            self.api()._cimi_post(self.nuvlaedge_id+"/commission", json=payload)
        except Exception as e:
            self.infra_logger.error(f"Could not commission with payload {payload}: {e}")
            return False

        if "vpn-csr" in payload:
            # get the respective VPN credential that was just created
            with open("{}/{}".format(self.data_volume, self.context)) as vsi:
                vpn_server_id = json.loads(vsi.read()).get("vpn-server-id")

            searcher_filter = self.build_vpn_credential_search_filter(vpn_server_id)

            attempts = 0
            credential_id = None
            while attempts <= 20:
                self.infra_logger.info("Getting VPN credential from Nuvla...")
                try:
                    credential_id = self.api().search("credential",
                                                      filter=searcher_filter,
                                                      last=1).resources[0].id
                    break
                except IndexError:
                    self.infra_logger.exception("Cannot find VPN credential in Nuvla "
                                                "after commissioning")
                    time.sleep(2)
                except Exception as e:
                    self.infra_logger.info("something %s" % e)

                attempts += 1

            if not credential_id:
                self.infra_logger.warning("Failing to provide necessary values for "
                                          "NuvlaEdge VPN client")
                return None

            vpn_credential = self.api()._cimi_get(credential_id)
            # save_vpn_credential
            vpn_server = self.api()._cimi_get(vpn_server_id)

            vpn_conf_endpoints = ''
            for connection in vpn_server["vpn-endpoints"]:
                vpn_conf_endpoints += \
                    "\n<connection>\nremote {} {} {}\n</connection>\n".format(
                        connection["endpoint"],
                        connection["port"],
                        connection["protocol"])

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
                        if key in old_conf and old_conf[key] == value:
                            continue

                        diff_conf[key] = value

                    return diff_conf
        except FileNotFoundError:
            self.infra_logger.info("Auto-commissioning the NuvlaEdge for the first time..")
            return current_conf

    def get_nuvlaedge_capabilities(self, commissioning_dict: dict):
        """ Finds the NuvlaEdge capabilities and adds them to the NB commissioning payload

        :param commissioning_dict: the commission payload, as a dict, to be changed in
        case there are capabilities
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
        if NuvlaEdgeCommon.ORCHESTRATOR not in ['docker', 'swarm']:
            return False

        if not container_api_port:
            container_api_port = self.compute_api_port

        compute_api_url = f'https://{self.compute_api}:{5000}'
        try:
            if self.container_runtime.client.containers.get(self.compute_api).status \
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
            self.infra_logger.info(f'Too many requests... Compute API not ready yet')
            return False

        return True

    def get_local_nuvlaedge_status(self) -> dict:
        """
        Reads the local nuvlaedge-status file

        Returns:
            dict: content of the file, or empty dict in case it doesn't exist
        """

        try:
            with open(self.nuvlaedge_status_file) as ns:
                return json.load(ns)
        except FileNotFoundError:
            return {}

    def get_node_role_from_status(self) -> str or None:
        """
        Look up the local nuvlaedge-status file and take the cluster-node-role value from
        there

        :return: node role
        """

        return self.get_local_nuvlaedge_status().get('cluster-node-role')

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

        cluster_info = self.container_runtime.get_cluster_info(
            default_cluster_name=f'cluster_{self.nuvlaedge_id}')

        node_info = self.container_runtime.get_node_info()
        node_id = self.container_runtime.get_node_id(node_info)

        # we only commission the cluster when the NuvlaEdge status
        # has already been updated with its "node-id"
        nuvlaedge_status = self.get_local_nuvlaedge_status()

        if not cluster_info:
            # it is not a manager but...
            if node_id and node_id == nuvlaedge_status.get('node-id'):
                # it is a worker, and NB status is aware of that, so we can update
                # the cluster with it
                return {
                    "cluster-worker-id": node_id,
                }
            else:
                return {}

        if nuvlaedge_status.get('node-id') in cluster_info.get('cluster-managers', []) \
                and node_id == nuvlaedge_status.get('node-id'):
            return cluster_info

        return {}

    def get_compute_endpoint(self, vpn_ip: str) -> tuple:
        """
        Find the endpoint and port of the compute API

        :returns tuple (api_endpoint, port)
        """
        container_api_ip, container_api_port = self.container_runtime.get_api_ip_port()

        api_endpoint = None
        ret_port = 5000
        if vpn_ip:
            api_endpoint = f"https://{vpn_ip}:{self.compute_api_port}"
            ret_port = self.compute_api_port
        elif container_api_ip and container_api_port:
            api_endpoint = f"https://{container_api_ip}:{5000}"

        self.infra_logger.debug(f'Compute API endpoint detected in: {api_endpoint}')
        return api_endpoint, ret_port

    def needs_partial_decommission(self, minimum_payload: dict, full_payload: dict,
                                   old_payload: dict):
        """
        For workers, sets the "remove" attr to instruct the partial decommission

        :param minimum_payload: base commissioning payload for request
        :param full_payload: full payload
        :param old_payload: payload from previous commissioning
        :return:
        """

        if self.get_node_role_from_status() != "worker":
            return

        full_payload['removed'] = \
            self.container_runtime.get_partial_decommission_attributes()
        if full_payload['removed'] != old_payload.get('removed', []):
            minimum_payload['removed'] = full_payload['removed']

        # remove the keys from the commission payload, to avoid confusion on the server
        # side
        for attr in minimum_payload.get('removed', []):
            try:
                full_payload.pop(attr)
                minimum_payload.pop(attr)
            except KeyError:
                pass

    def commissioning_attr_has_changed(self, current: dict, old: dict, attr_name: str,
                                       payload: dict,
                                       compare_with_nb_resource: bool = False):
        """
        Compares the current attribute value with the old one, and if different, adds it
        to the commissioning payload

        Args:
            current (dict): current commissioning attributes
            old (dict): previous commissioning attributes
            attr_name (str): name of the attribute to be compared
            payload (dict): minimum commissioning payload
            compare_with_nb_resource (bool): if True, will lookup the local .context file
            and check if attr has changed. NOTE: this flag make the check ignore whatever
            the previous commission was
        """

        if compare_with_nb_resource:
            with open(f'{self.data_volume}/{self.context}') as f:
                # overwrite the old commissioning value with the one from the NB resource
                # (source of truth)
                old_value = json.load(f).get(attr_name)
                if old_value:
                    old[attr_name] = old_value

        if isinstance(current[attr_name], str):
            if current[attr_name] != old.get(attr_name):
                payload[attr_name] = current[attr_name]
        elif isinstance(current[attr_name], list):
            if sorted(current[attr_name]) != sorted(old.get(attr_name, [])):
                payload[attr_name] = current[attr_name]

    def try_commission(self):
        """ Checks whether any of the system configurations have changed
        and if so, returns True or False """
        cluster_join_tokens = self.container_runtime.get_join_tokens()
        cluster_info = self.needs_cluster_commission()

        # initialize the commissioning payload
        commission_payload = cluster_info.copy()

        old_commission_payload = self.read_commissioning_file()
        minimum_commission_payload = {} if cluster_info.items() <= old_commission_payload.items() else cluster_info.copy()

        my_vpn_ip = self.telemetry_instance.get_vpn_ip()
        api_endpoint, container_api_port = self.get_compute_endpoint(my_vpn_ip)

        current_data = self.api().get(self.nuvlaedge_id)
        if current_data.data.get('tags'):
            temp_list: set = set(current_data.data.get('tags', []))
            for i in self.container_runtime.get_node_labels():
                temp_list.add(i)

            commission_payload["tags"] = list(temp_list)
        else:
            commission_payload["tags"] = list(self.container_runtime.get_node_labels())
        self.commissioning_attr_has_changed(
            commission_payload,
            old_commission_payload,
            "tags",
            minimum_commission_payload)

        infra_service = {}
        if self.compute_api_is_running(container_api_port):
            infra_service = \
                self.container_runtime.define_nuvla_infra_service(api_endpoint,
                                                                  self.get_tls_keys())
        # 1st time commissioning the IS, so we need to also pass the keys, even if they
        # haven't changed
        infra_diff = \
            {k: v for k, v in infra_service.items() if v != old_commission_payload.get(k)}

        if self.container_runtime.infra_service_endpoint_keyname in \
                old_commission_payload:
            minimum_commission_payload.update(infra_diff)
        else:
            minimum_commission_payload.update(infra_service)

        commission_payload.update(infra_service)

        # atm, it isn't clear whether these will make sense for k8s
        # if they do, then this block should be moved to an abstractmethod of the
        # ContainerRuntime
        if len(cluster_join_tokens) > 1:
            self.swarm_token_diff(cluster_join_tokens[0], cluster_join_tokens[1])
            commission_payload.update({
                self.container_runtime.join_token_manager_keyname: cluster_join_tokens[0],
                self.container_runtime.join_token_worker_keyname: cluster_join_tokens[1]
            })

            self.commissioning_attr_has_changed(
                commission_payload,
                old_commission_payload,
                self.container_runtime.join_token_manager_keyname,
                minimum_commission_payload)
            self.commissioning_attr_has_changed(
                commission_payload,
                old_commission_payload,
                self.container_runtime.join_token_worker_keyname,
                minimum_commission_payload)

        self.get_nuvlaedge_capabilities(commission_payload)
        # capabilities should always be commissioned when infra is also being commissioned
        if any(k in minimum_commission_payload for k in infra_service):
            minimum_commission_payload['capabilities'] = \
                commission_payload.get('capabilities', [])
        else:
            self.commissioning_attr_has_changed(
                commission_payload, old_commission_payload,
                "capabilities", minimum_commission_payload,
                compare_with_nb_resource=True)

        # if this node is a worker, them we must force remove some assets
        self.needs_partial_decommission(minimum_commission_payload, commission_payload,
                                        old_commission_payload)

        if self.do_commission(minimum_commission_payload):
            self.write_file("{}/{}".format(self.data_volume, self.commissioning_file),
                            commission_payload,
                            is_json=True)

    def build_vpn_credential_search_filter(self, vpn_server_id):
        """ Simply build the API query for searching this NuvlaEdge's VPN credential

        :param vpn_server_id: ID of the VPN server
        :return str
        """

        return f'method="create-credential-vpn-nuvlabox" and ' \
               f'vpn-common-name="{self.nuvlaedge_id}" and parent="{vpn_server_id}"'

    def validate_local_vpn_credential(self, online_vpn_credential: dict):
        """
        When the VPN credential exists in Nuvla, this function checks whether the local
        copy of that credential matches. If it does not, issue a VPN recommissioning

        :param online_vpn_credential: VPN credential resource received from Nuvla
        :return:
        """
        with open(self.vpn_credential) as vpn_local:
            local_vpn_credential = json.loads(vpn_local.read())

        if online_vpn_credential['updated'] != local_vpn_credential['updated']:
            self.infra_logger.warning(f"VPN credential has been modified in Nuvla at "
                                      f"{online_vpn_credential['updated']}. "
                                      f"Recommissioning")
            # Recommission
            self.commission_vpn()
            remove(self.vpn_credential)
            return None
            # else, do nothing because nothing has changed

    def fix_vpn_credential_mismatch(self, online_vpn_credential: dict):
        """
        When a VPN credential exists in Nuvla but not locally, there is a mismatch to be
        investigated. This function will double-check the local VPN client state,
        re-commission the VPN credential if needed, and finally save the right VPN
        credential locally for future reference

        :param online_vpn_credential: VPN credential resource received from Nuvla
        :return:
        """
        try:
            vpn_client_running = self.container_runtime.is_vpn_client_running()
        except docker.errors.NotFound:
            vpn_client_running = False
            self.infra_logger.info("VPN client is not running")

        if vpn_client_running and self.telemetry_instance.get_vpn_ip():
            # just save a copy of the VPN credential locally
            self.write_file(self.vpn_credential, online_vpn_credential, is_json=True)
            self.infra_logger.info(f"VPN client is now running. Saving VPN credential "
                                   f"locally at {self.vpn_credential}")
        else:
            # there is a VPN credential in Nuvla, but not locally, and the VPN client
            # is not running maybe something went wrong, just recommission
            self.infra_logger.warning("The local VPN client is either not running or "
                                      "missing its configuration. Forcing VPN "
                                      "recommissioning...")
            self.commission_vpn()

    def watch_vpn_credential(self, vpn_is_id=None):
        """ Watches the VPN credential in Nuvla for changes

        :param vpn_is_id: VPN server ID
        """

        if not vpn_is_id:
            return None

        search_filter = self.build_vpn_credential_search_filter(vpn_is_id)
        self.infra_logger.debug("Watching VPN credential in Nuvla...")
        try:
            credential_id = self.api().search("credential",
                                              filter=search_filter,
                                              last=1).resources[0].id
            self.infra_logger.debug("Found VPN credential ID %s" % credential_id)
        except IndexError:
            credential_id = None

        if not credential_id:
            # If you cannot find a VPN credential in Nuvla, then it is either in the
            # process of being created or it has been removed from Nuvla
            self.infra_logger.info("VPN server is set but cannot find VPN credential in "
                                   "Nuvla. Commissioning VPN...")

            if path.exists(self.vpn_credential) and \
                    stat(self.vpn_credential).st_size != 0:
                self.infra_logger.warning("NOTE: VPN credential exists locally, so it "
                                          "was removed from Nuvla")

            self.commission_vpn()
        else:
            vpn_credential_nuvla = self.api()._cimi_get(credential_id)

            # IF there is a VPN credential in Nuvla:
            #  - if we also have one locally, BUT is different, then recommission
            if path.exists(self.vpn_credential) \
                    and stat(self.vpn_credential).st_size != 0 \
                    and path.exists(self.vpn_client_conf_file):
                self.validate_local_vpn_credential(vpn_credential_nuvla)
            else:
                # - IF we don't have it locally, but there's one in Nuvla, then:
                #     - IF the vpn-client is already running, then all is good, just
                #     save the VPN credential locally
                self.infra_logger.warning("VPN credential exists in Nuvla, but not "
                                          "locally")
                self.fix_vpn_credential_mismatch(vpn_credential_nuvla)

    def set_immutable_ssh_key(self):
        """
        Takes a public SSH key from env and adds it to the installing host user.
        This is only done once, at installation time.

        :return:
        """

        if path.exists(self.ssh_flag):
            self.infra_logger.debug("Immutable SSH key has already been processed at "
                                    "installation time")
            with open(self.ssh_flag) as sshf:
                original_ssh_key = sshf.read()
                if self.ssh_pub_key != original_ssh_key:
                    self.infra_logger.warning(f'Received new SSH key but the original '
                                              f'{original_ssh_key} is immutable.Ignoring')
            return

        event = {
            "category": "action",
            "content": {
                "resource": {
                    "href": self.nuvlaedge_id
                },
                "state": f"Unknown problem while setting immutable SSH key"
            },
            "severity": "high",
            "timestamp": datetime.utcnow().strftime(self.nuvla_timestamp_format)
        }

        if self.ssh_pub_key and self.installation_home:
            ssh_folder = f"{self.hostfs}{self.installation_home}/.ssh"
            if not path.exists(ssh_folder):
                event['content']['state'] = f"Cannot set immutable SSH key because " \
                                            f"{ssh_folder} does not exist"

                self.push_event(event)
                return

            with open(f'{self.data_volume}/{self.context}') as nb:
                nb_owner = json.load(nb).get('owner')

            event_owners = [nb_owner, self.nuvlaedge_id] if nb_owner \
                else [self.nuvlaedge_id]
            event['acl'] = {'owners': event_owners}

            self.infra_logger.info(f'Setting immutable SSH key {self.ssh_pub_key} for '
                                   f'{self.installation_home}')
            try:
                with NuvlaEdgeCommon.timeout(10):
                    if not self.container_runtime.install_ssh_key(self.ssh_pub_key,
                                                                  ssh_folder):
                        return
            except Exception as e:
                msg = f'An error occurred while setting immutable SSH key: {str(e)}'
                self.infra_logger.error(msg)
                event['content']['state'] = msg
                self.push_event(event)

            self.write_file(self.ssh_flag, self.ssh_pub_key)

    def run(self) -> None:
        """
        Threads the commissioning cycles, so that they don't interfere with the main
        telemetry cycle
        """
        while True:
            try:
                self.try_commission()
            except RuntimeError as ex:
                self.infra_logger.exception('Error while trying to commission NuvlaEdge',
                                            ex)
            time.sleep(self.refresh_period)
