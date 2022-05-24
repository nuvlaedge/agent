#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Activation

It takes care of activating a new NuvlaBox
"""

import logging
import requests

from agent.common import NuvlaBoxCommon


class Activate(NuvlaBoxCommon.NuvlaBoxCommon):
    """ The Activate class, which includes all methods and
    properties necessary to activate a NuvlaBox

    Attributes:
        data_volume: path to shared NuvlaBox data
    """

    def __init__(self, data_volume):
        """ Constructs an Activation object """

        # self.data_volume = data_volume
        # self.activation_flag = "{}/.activated".format(self.data_volume)
        super().__init__(shared_data_volume=data_volume)

        # self.api = nb.ss_api() if not api else api
        self.user_info = {}

    def activation_is_possible(self):
        """ Checks for any hints of a previous activation
        or any other conditions that might influence the
        first time activation of the NuvlaBox

        :return boolean and user info is available"""

        if self.get_operational_status() == "UNKNOWN":
            return False, self.user_info

        try:
            self.user_info = self.read_json_file(self.activation_flag)

            logging.warning("{} already exists. Re-activation is not possible!".format(self.activation_flag))
            logging.info("NuvlaBox credential: {}".format(self.user_info["api-key"]))
            return False, self.user_info
        except FileNotFoundError:
            # file doesn't exist yet,
            # But maybe the API was provided via env?
            api_key, api_secret = self.get_api_keys()
            if api_key and api_secret:
                logging.info(f'Found API key set in environment, with key value {api_key}')
                self.user_info = {
                    "api-key": api_key,
                    "secret-key": api_secret
                }

                self.write_json_to_file(self.activation_flag, self.user_info)

                return False, self.user_info
            
            return True, self.user_info

    def activate(self):
        """ Makes the anonymous call to activate the NuvlaBox """

        logging.info('Activating "{}"'.format(self.nuvlabox_id))

        try:
            self.user_info = self.api()._cimi_post('{}/activate'.format(self.nuvlabox_id))
        except requests.exceptions.SSLError:
            self.shell_execute(["timeout", "3s", "/lib/systemd/systemd-timesyncd"])
            self.user_info = self.api()._cimi_post('{}/activate'.format(self.nuvlabox_id))
        except requests.exceptions.ConnectionError as conn_err:
            logging.error("Can not reach out to Nuvla at {}. Error: {}".format(self.nuvla_endpoint, conn_err))
            raise

        # Flags that the activation has been done
        self.write_json_to_file(self.activation_flag, self.user_info)

        return self.user_info

    def create_nb_document_file(self, nuvlabox_resource: dict) -> dict:
        """ Writes contextualization file with NB resource content

        :param nuvlabox_resource: nuvlabox resource data
        :return copy of the old NB resource context which is being overwritten
        """
        context_file = "{}/{}".format(self.data_volume, self.context)

        logging.info('Managing NB context file {}'.format(context_file))

        try:
            current_context = self.read_json_file(context_file)
        except (ValueError, FileNotFoundError):
            logging.warning("Writing {} for the first time".format(context_file))
            current_context = {}

        self.write_json_to_file(context_file, nuvlabox_resource)

        return current_context

    def vpn_commission_if_needed(self, current_nb_resource: dict, old_nb_resource: dict):
        """
        Checks if the VPN server ID has changed in the NB resource, and if so, asks for VPN commissioning

        :param current_nb_resource: current NuvlaBox resource, from Nuvla
        :param old_nb_resource: old content of the NuvlaBox resource
        :return:
        """
        if current_nb_resource.get("vpn-server-id") != old_nb_resource.get("vpn-server-id"):
            logging.info(f'VPN Server ID has been added/changed in Nuvla: {current_nb_resource.get("vpn-server-id")}')

            self.commission_vpn()

    def get_nuvlabox_info(self):
        """ Retrieves the respective resource from Nuvla """

        return self.api().get(self.nuvlabox_id).data

    def update_nuvlabox_resource(self) -> tuple:
        """ Updates the static information about the NuvlaBox

        :return: current and old NuvlaBox resources
        """

        self.authenticate(self.api(), self.user_info["api-key"], self.user_info["secret-key"])
        nuvlabox_resource = self.get_nuvlabox_info()

        old_nuvlabox_resource = self.create_nb_document_file(nuvlabox_resource)

        return nuvlabox_resource, old_nuvlabox_resource
