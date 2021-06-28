#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Activation

It takes care of activating a new NuvlaBox
"""

import json
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
            with open(self.activation_flag) as a:
                self.user_info = json.loads(a.read())

            logging.warning("{} already exists. Re-activation is not possible!".format(self.activation_flag))
            logging.info("NuvlaBox credential: {}".format(self.user_info["api-key"]))
            return False, self.user_info
        except FileNotFoundError:
            # file doesn't exist yet, so it was not activated in the past
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
        with open(self.activation_flag, 'w') as a:
            a.write(json.dumps(self.user_info))

        # Also store the Nuvla connection details for future restarts
        with open(self.nuvlabox_nuvla_configuration, 'w') as nuvla_conf:
            conf = f"{self.nuvla_endpoint_key}={self.nuvla_endpoint}\n\
{self.nuvla_endpoint_insecure_key}={str(self.nuvla_endpoint_insecure)}"
            nuvla_conf.write(conf)

        return self.user_info

    def create_nb_document_file(self, nuvlabox_resource):
        """ Writes contextualization file with NB resource content

        :param nuvlabox_resource: nuvlabox resource data
        """

        context_file = "{}/{}".format(self.data_volume, self.context)

        logging.info('Managing NB context file {}'.format(context_file))

        try:
            with open(context_file) as c:
                current_context = json.loads(c.read())
        except (ValueError, FileNotFoundError):
            logging.warning("Writing {} for the first time".format(context_file))
            current_context = {}

        current_vpn_is_id = current_context.get("vpn-server-id")

        with open(context_file, 'w') as cw:
            cw.write(json.dumps(nuvlabox_resource))

        if nuvlabox_resource.get("vpn-server-id") != current_vpn_is_id:
            logging.info('VPN Server ID has been added/changed in Nuvla: {}'
                         .format(nuvlabox_resource.get("vpn-server-id")))

            self.commission_vpn()

    def get_nuvlabox_info(self):
        """ Retrieves the respective resource from Nuvla """

        return self.api().get(self.nuvlabox_id).data

    def update_nuvlabox_resource(self):
        """ Updates the static information about the NuvlaBox

        :return: nuvlabox-status ID
        """

        self.authenticate(self.api(), self.user_info["api-key"], self.user_info["secret-key"])
        nuvlabox_resource = self.get_nuvlabox_info()

        self.create_nb_document_file(nuvlabox_resource)

        return nuvlabox_resource["nuvlabox-status"]

    def update_nuvlabox_info(self, nuvlabox_resource):
        """ Takes the nuvlabox_resource and updates it with static and
        device specific information """

        cpuinfo = self.get_cpuinfo()
        # nuvlabox_resource.setdefault('hwRevisionCode', cpuinfo["Revision"])
        nuvlabox_resource.setdefault('os-version', self.container_runtime.get_host_os())
        # nuvlabox_resource.setdefault('manufacturerSerialNumber', cpuinfo["Serial"])
        return nuvlabox_resource

    @staticmethod
    def get_cpuinfo():
        """ Static method to fetch CPU information """

        cpuinfo = {}
        with open("/proc/cpuinfo", "r") as cpui:
            lines = cpui.read().splitlines()
            for l in lines:
                if l.startswith("Revision"):
                    cpuinfo["Revision"] = l.split(":")[-1].replace(" ", "")
                if l.startswith("Serial"):
                    cpuinfo["Serial"] = l.split(":")[-1].replace(" ", "")
        return cpuinfo

