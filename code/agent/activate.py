#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaEdge Activation

It takes care of activating a new NuvlaEdge
"""

import logging
import requests

from agent.common import NuvlaEdgeCommon


class Activate(NuvlaEdgeCommon.NuvlaEdgeCommon):
    """ The Activate class, which includes all methods and
    properties necessary to activate a NuvlaEdge

    Attributes:
        data_volume: path to shared NuvlaEdge data
    """

    def __init__(self, data_volume):
        """ Constructs an Activation object """

        super().__init__(data_volume=data_volume)

        self.activate_logger: logging.Logger = logging.getLogger(__name__)
        self.user_info = {}

    def activation_is_possible(self):
        """ Checks for any hints of a previous activation
        or any other conditions that might influence the
        first time activation of the NuvlaEdge

        :return boolean and user info is available"""

        try:
            self.user_info = self.read_json_file(self.activation_flag)

            self.activate_logger.warning("{} already exists. Re-activation is not possible!".format(self.activation_flag))
            self.activate_logger.info("NuvlaEdge credential: {}".format(self.user_info["api-key"]))
            return False, self.user_info
        except FileNotFoundError:
            # file doesn't exist yet,
            # But maybe the API was provided via env?
            api_key, api_secret = self.get_api_keys()
            if api_key and api_secret:
                self.activate_logger.info(f'Found API key set in environment, with key'
                                          f' value {api_key}')
                self.user_info = {
                    "api-key": api_key,
                    "secret-key": api_secret
                }

                self.write_json_to_file(self.activation_flag, self.user_info)

                return False, self.user_info

            return True, self.user_info

    def activate(self):
        """ Makes the anonymous call to activate the NuvlaEdge """

        self.activate_logger.info('Activating "{}"'.format(self.nuvlaedge_id))

        try:
            self.user_info = self.api()._cimi_post('{}/activate'.format(self.nuvlaedge_id))
        except requests.exceptions.SSLError:
            self.shell_execute(["timeout", "3s", "/lib/systemd/systemd-timesyncd"])
            self.user_info = self.api()._cimi_post('{}/activate'.format(self.nuvlaedge_id))
        except requests.exceptions.ConnectionError as conn_err:
            self.activate_logger.error("Can not reach out to Nuvla at {}. Error: {}"
                                       .format(self.nuvla_endpoint, conn_err))
            raise

        # Flags that the activation has been done
        self.write_json_to_file(self.activation_flag, self.user_info)

        return self.user_info

    def create_nb_document_file(self, nuvlaedge_resource: dict) -> dict:
        """ Writes contextualization file with NB resource content

        :param nuvlaedge_resource: nuvlaedge resource data
        :return copy of the old NB resource context which is being overwritten
        """
        context_file = "{}/{}".format(self.data_volume, self.context)

        self.activate_logger.info('Managing NB context file {}'.format(context_file))

        try:
            current_context = self.read_json_file(context_file)
        except (ValueError, FileNotFoundError):
            self.activate_logger.warning("Writing {} for the first "
                                         "time".format(context_file))
            current_context = {}

        self.write_json_to_file(context_file, nuvlaedge_resource)

        return current_context

    def vpn_commission_if_needed(self, current_nb_resource: dict, old_nb_resource: dict):
        """
        Checks if the VPN server ID has changed in the NB resource, and if so, asks for
        VPN commissioning

        :param current_nb_resource: current NuvlaEdge resource, from Nuvla
        :param old_nb_resource: old content of the NuvlaEdge resource
        :return:
        """
        if current_nb_resource.get("vpn-server-id") != \
                old_nb_resource.get("vpn-server-id"):
            self.activate_logger.info(f'VPN Server ID has been added/changed in Nuvla: '
                                      f'{current_nb_resource.get("vpn-server-id")}')

            self.commission_vpn()

    def get_nuvlaedge_info(self):
        """ Retrieves the respective resource from Nuvla """

        return self.api().get(self.nuvlaedge_id).data

    def update_nuvlaedge_resource(self) -> tuple:
        """ Updates the static information about the NuvlaEdge

        :return: current and old NuvlaEdge resources
        """

        self.authenticate(self.api(), self.user_info["api-key"], self.user_info["secret-key"])
        nuvlaedge_resource = self.get_nuvlaedge_info()

        old_nuvlaedge_resource = self.create_nb_document_file(nuvlaedge_resource)

        return nuvlaedge_resource, old_nuvlaedge_resource
