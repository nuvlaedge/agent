#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Activation
It takes care of activating a new NuvlaBox
"""

import random
import string
import logging
import requests
from ..common import nuvlabox as nb

LOG = '/var/log/nuvlabox-activate.log'

class Activate(object):
    def activate(api):
        logging.info('Activating "{}"'.format(nb.NUVLABOX_ID))
        # cimi_operation isn't used because anonyme don't have right to get the resource to extract operation href
        try:
            user_info = api._cimi_post('{}/activate'.format(nb.NUVLABOX_ID))
        except requests.exceptions.SSLError:
            nb.shell_execute(["timeout", "3s", "/lib/systemd/systemd-timesyncd"])
            user_info = api._cimi_post('{}/activate'.format(nb.NUVLABOX_ID))
        except:
            raise
        return user_info


    def set_default(resource, key, default_value):
        if not resource.get(key):
            resource[key] = default_value
        return resource[key]


    def random_chars(length=12):
        return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(length)])


    def get_cpuinfo():
        cpuinfo = {}
        with open("/proc/cpuinfo", "r") as cpui:
            lines = cpui.read().splitlines()
            for l in lines:
                if l.startswith("Revision"):
                    cpuinfo["Revision"] = l.split(":")[-1].replace(" ","")
                if l.startswith("Serial"):
                    cpuinfo["Serial"] = l.split(":")[-1].replace(" ","")
        return cpuinfo


    def get_nuvlabox_release():
        with open("/etc/nuvlabox-release", "r") as nbr:
            return nbr.read().splitlines()[0]


    def update_nuvlabox_info(nuvlabox_info):
        cpuinfo = get_cpuinfo()
        set_default(nuvlabox_info, 'loginPassword', str(nb.nuvlaboxdb.read("loginPassword")) )
        set_default(nuvlabox_info, 'loginUsername', str(nb.nuvlaboxdb.read("loginUsername")) )
        set_default(nuvlabox_info, 'hwRevisionCode', cpuinfo["Revision"])
        set_default(nuvlabox_info, 'OSVersion', get_nuvlabox_release())
        set_default(nuvlabox_info, 'manufacturerSerialNumber', cpuinfo["Serial"])
        return nuvlabox_info


    def main():
        description = 'Activate the NuvlaBox and retreive the configuration'
        args = nb.arguments(description, LOG).parse_args()

        try:
            nb.logger(nb.get_log_level(args), args.log_file)
            api = nb.ss_api()

            user_info = activate(api)
            nb.create_user_file(user_info)

            nb.authenticate(api)

            nuvlabox_info = nb.get_nuvlabox_info(api)
            update_nuvlabox_info(nuvlabox_info)
            api.cimi_edit(nb.NUVLABOX_ID, nuvlabox_info)
            nb.create_context_file(nuvlabox_info)

        except Exception:
            logging.exception('Error while activating the NuvlaBox')
            raise
