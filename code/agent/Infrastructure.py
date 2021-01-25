#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Infrastructure

It takes care of updating the NuvlaBox infrastructure services
and respective credentials in Nuvla
"""

import logging
import docker
import json
import time
from agent.common import NuvlaBoxCommon
from agent.Telemetry import Telemetry
from os import path, stat, remove

class Infrastructure(NuvlaBoxCommon.NuvlaBoxCommon):
    """ The Infrastructure class includes all methods and
    properties necessary update the infrastructure services
    and respective credentials in Nuvla, whenever the local
    configurations change

    """

    def __init__(self, data_volume):
        """ Constructs an Infrastructure object, with a status placeholder

        :param data_volume: shared volume
        """

        super().__init__(shared_data_volume=data_volume)
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

    def is_kubernetes_running(self):
        """ Tries to infer whether there is a k8s cluster running in the host
        and if so, it tries to retrieve its API endpoint and client certificates

        :returns dict {:endpoint, :ca, :cert, :key}"""

        k8s_apiserver_container_label = "io.kubernetes.container.name=kube-apiserver"
        k8s_apiservers = self.docker_client.containers.list(filters={"label": k8s_apiserver_container_label})

        k8s_cluster_info = {}
        if not k8s_apiservers:
            return k8s_cluster_info

        arg_address = "advertise-address"
        arg_port = "secure-port"
        arg_ca = "client-ca-file"
        arg_cert = "kubelet-client-certificate"
        arg_key = "kubelet-client-key"
        # just in case there is more than one k8s config, we want to get the first one that looks healthy
        for api in k8s_apiservers:
            try:
                inspect = self.docker_client.api.inspect_container(api.id)
            except docker.errors.NotFound:
                logging.warning(f'Error inspecting container {api.id} while looking up for k8s cluster')
                continue

            args_list = inspect.get('Args', [])
            # convert list to dict
            try:
                args = { args_list[i].split('=')[0].lstrip("--"): args_list[i].split('=')[-1] for i in range(0, len(args_list)) }
            except IndexError:
                logging.warning(f'Unable to infer k8s cluster info from apiserver arguments {args_list}')
                continue

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
                    'endpoint': k8s_endpoint,
                    'ca': k8s_client_ca,
                    'cert': k8s_client_cert,
                    'key': k8s_client_key
                })
                # if we got here, then it's very likely that the k8s cluster is up and running, no need to go further
                break
            except (KeyError, FileNotFoundError) as e:
                logging.warning(f'Cannot destructure or access certificates from k8s apiserver arguments {args}. {str(e)}')
                continue

        return k8s_cluster_info

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

    def do_commission(self, payload):
        """ Perform the operation

        :param payload: commissioning payload
        :return
        """

        try:
            self.api()._cimi_post(self.nuvlabox_id+"/commission", json=payload)
        except Exception as e:
            logging.error("Could not commission with payload {}: {}".format(payload, e))
            return False

        if "vpn-csr" in payload:
            # get the respective VPN credential that was just created
            with open("{}/{}".format(self.data_volume, self.context)) as vsi:
                vpn_server_id = json.loads(vsi.read()).get("vpn-server-id")
            # vpn_server_id = json.loads(open("{}/{}".format(self.data_volume, self.context)).read())["vpn-server-id"]

            searcher_filter = self.build_vpn_credential_search_filter(vpn_server_id)

            attempts = 0
            credential_id = None
            while attempts <= 20:
                logging.info("Getting VPN credential from Nuvla...")
                try:
                    credential_id = self.api().search("credential", filter=searcher_filter, last=1).resources[0].id
                    break
                except IndexError:
                    logging.info("*****************")

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

    def get_labels(self):
        """ Gets all the Docker node labels """
        nuvla_tags = []

        try:
            node_id = self.docker_client.info()["Swarm"]["NodeID"]
            container_labels = self.docker_client.api.inspect_node(node_id)["Spec"]["Labels"]
        except docker.errors.APIError:
            logging.exception("Cannot get node labels")
            return nuvla_tags

        for label, value in container_labels.items():
            if value:
                nuvla_tags.append("{}={}".format(label, value))
            else:
                nuvla_tags.append(label)

        return nuvla_tags

    def needs_commission(self, current_conf):
        """ Check whether the current commission data structure
        has changed wrt to the previous one

        :param current_conf: current commissioning data
        :return False when commissioning is not needed, or the changed attributes otherwise
        """

        try:
            with open("{}/{}".format(self.data_volume, self.commissioning_file)) as r:
                old_conf = json.loads(r.read())
                if current_conf == old_conf:
                    return False
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

    def has_nuvla_job_pull(self):
        """ Checks if the job-engine-lite has been deployed alongside the NBE

        :return:
        """

        job_engine_lite_container = "nuvlabox-job-engine-lite"
        try:
            container = self.docker_client.containers.get(job_engine_lite_container)
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logging.error(f"Unable to search for container {job_engine_lite_container}. Reason: {str(e)}")
            return False

        try:
            if container.status.lower() == "paused":
                self.job_engine_lite_image = container.attrs['Config']['Image']
                return True
        except (AttributeError, KeyError):
            return False

        return False

    def get_nuvlabox_capabilities(self, commissioning_dict: dict):
        """ Finds the NuvlaBox capabilities and adds them to the NB commissioning payload

        :param commissioning_dict: the commission payload, as a dict, to be changed in case there are capabilities
        :return:
        """

        # NUVLA_JOB_PULL if job-engine-lite has been deployed with the NBE
        commissioning_dict['capabilities'] = []
        if self.has_nuvla_job_pull():
            commissioning_dict['capabilities'].append('NUVLA_JOB_PULL')

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

        k8s_config = self.is_kubernetes_running()
        if k8s_config:
            commission_payload["kubernetes-endpoint"] = k8s_config['endpoint']
            commission_payload["kubernetes-client-ca"] = k8s_config['ca']
            commission_payload["kubernetes-client-cert"] = k8s_config['cert']
            commission_payload["kubernetes-client-key"] = k8s_config['key']

        self.get_nuvlabox_capabilities(commission_payload)

        tags = self.get_labels()
        commission_payload["tags"] = tags

        minimum_commission_payload = self.needs_commission(commission_payload)
        if minimum_commission_payload:
            logging.info("Commissioning the NuvlaBox...{}".format(minimum_commission_payload))
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
            logging.warning("VPN server is set but cannot find VPN credential in Nuvla")

            # IF there isn't yet a VPN credential stored locally, then maybe the NB is still commissioning for
            # the 1st time
            if path.exists(self.vpn_credential) and stat(self.vpn_credential).st_size != 0:
                logging.warning("VPN credential exists locally, so it was removed from Nuvla. Recommissioning...")
            else:
                logging.info("NuvlaBox is in the process of commissioning, so VPN credential should get here soon")
                return None

            self.write_file(self.vpn_infra_file, vpn_is_id)
        else:
            vpn_credential_nuvla = self.api()._cimi_get(credential_id)

            # IF there is a VPN credential in Nuvla:
            #  - if we also have one locally, BUT is different, then recommission
            if path.exists(self.vpn_credential) and stat(self.vpn_credential).st_size != 0:
                with open(self.vpn_credential) as vpn_local:
                    local_vpn_credential = json.loads(vpn_local.read())

                if vpn_credential_nuvla['updated'] != local_vpn_credential['updated']:
                    logging.warning("VPN credential has been modified in Nuvla at {}. Recommissioning"
                                    .format(vpn_credential_nuvla['updated']))
                    # Recommission
                    self.write_file(self.vpn_infra_file, vpn_is_id)
                    remove(self.vpn_credential)
                    return None
                    # else, do nothing cause nothing has changed
            else:
                # - IF we don't have it locally, but there's one in Nuvla, then:
                #     - IF the vpn-client is already running, then all is good, just save the VPN credential locally
                logging.warning("VPN credential exists in Nuvla, but not locally")

                dc = docker.from_env()
                try:
                    vpn_client_running = True if dc.containers.get("vpn-client").status == 'running' else False
                except docker.errors.NotFound as e:
                    vpn_client_running = False
                    logging.info("VPN client is not running")

                if vpn_client_running:
                    # just save a copy of the VPN credential locally
                    self.write_file(self.vpn_credential, vpn_credential_nuvla, is_json=True)
                    logging.info("VPN client is now running. Saving VPN credential locally at {}"
                                    .format(self.vpn_credential))
                else:
                    # there is a VPN credential in Nuvla, but not locally, and the VPN client is not running
                    # maybe something went wrong, just recommission
                    logging.error("Trying to fix local VPN client by recommissioning...")
                    self.write_file(self.vpn_infra_file, vpn_is_id)
