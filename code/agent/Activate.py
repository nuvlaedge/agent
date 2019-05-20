#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Activation

It takes care of activating a new NuvlaBox
"""

import json
import logging
import requests
import docker
from agent.common import nuvlabox as nb


class Activate(object):
    """ The Activate class, which includes all methods and
    properties necessary to activate a NuvlaBox

    Attributes:
        data_volume: path to shared NuvlaBox data
    """

    def __init__(self, data_volume, api=None):
        """ Constructs an Activation object """

        self.data_volume = data_volume
        self.activation_flag = "{}/.activated".format(self.data_volume)
        self.api = nb.ss_api() if not api else api
        self.user_info = {}

    def activation_is_possible(self):
        """ Checks for any hints of a previous activation
        or any other conditions that might influence the
        first time activation of the NuvlaBox

        :return boolean and user info is available"""

        if nb.get_operational_status(self.data_volume) == "UNKNOWN":
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

        logging.info('Activating "{}"'.format(nb.NUVLABOX_RECORD_ID))

        try:
            self.user_info = self.api._cimi_post('{}/activate'.format(nb.NUVLABOX_RECORD_ID))
        except requests.exceptions.SSLError:
            nb.shell_execute(["timeout", "3s", "/lib/systemd/systemd-timesyncd"])
            self.user_info = self.api._cimi_post('{}/activate'.format(nb.NUVLABOX_RECORD_ID))
        except requests.exceptions.ConnectionError as conn_err:
            logging.error("Can not reach out to Nuvla at {}. Error: {}".format(nb.NUVLA_ENDPOINT, conn_err))
            raise

        # Flags that the activation has been done
        with open(self.activation_flag, 'w') as a:
            a.write(json.dumps(self.user_info))

        return self.user_info

    def update_nuvlabox_record(self):
        """ Updates the static information about the NuvlaBox

        :return: nuvlabox-status ID
        """

        nb.authenticate(self.api, self.user_info["api-key"], self.user_info["secret-key"])
        nuvlabox_record = nb.get_nuvlabox_info(self.api)
        self.update_nuvlabox_info(nuvlabox_record)
        logging.info("Updating {} with {}".format(nb.NUVLABOX_RECORD_ID, nuvlabox_record))
        self.api._cimi_put(nb.NUVLABOX_RECORD_ID, json=nuvlabox_record)
        nb.create_context_file(nuvlabox_record, data_volume=self.data_volume)

        return nuvlabox_record["nuvlabox-status"]


    def update_nuvlabox_info(self, nuvlabox_record):
        """ Takes the nuvlabox_record resource and updates it with static and
        device specific information """

        cpuinfo = self.get_cpuinfo()
        # nuvlabox_record.setdefault('hwRevisionCode', cpuinfo["Revision"])
        nuvlabox_record.setdefault('os-version', self.get_os())
        # nuvlabox_record.setdefault('manufacturerSerialNumber', cpuinfo["Serial"])
        return nuvlabox_record

    @staticmethod
    def get_cpuinfo():
        """ Static method to fetch CPU information """

        cpuinfo = {}
        with open("/proc/cpuinfo", "r") as cpui:
            lines = cpui.read().splitlines()
            for l in lines:
                if l.startswith("Revision"):
                    cpuinfo["Revision"] = l.split(":")[-1].replace(" ","")
                if l.startswith("Serial"):
                    cpuinfo["Serial"] = l.split(":")[-1].replace(" ","")
        return cpuinfo

    @staticmethod
    def get_os():
        """ Gets the host OS """

        client = docker.from_env()
        return "{} {}".format(client.info()["OperatingSystem"], client.info()["KernelVersion"])

