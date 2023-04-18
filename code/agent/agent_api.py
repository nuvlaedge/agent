#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaEdge Agent API

List of functions to support the NuvlaEdge Agent API instantiated by app.py
"""

import json

from nuvlaedge.common.constant_files import FILE_NAMES

from agent.common import NuvlaEdgeCommon, util

nuvla_resource = "nuvlabox-peripheral"
NB = NuvlaEdgeCommon.NuvlaEdgeCommon()


def save_vpn_ip(ip):
    """
    Take the IP as a string and writes it into the shared volume

    :param ip: string
    :return:
    """
    util.atomic_write(FILE_NAMES.VPN_IP_FILE, str(ip))


def save_vulnerabilities(vulnerabilities):
    """
    Dumps vulnerabilities into a file

    :param vulnerabilities: as JSON
    :return:
    """
    util.atomic_write(FILE_NAMES.VULNERABILITIES_FILE, json.dumps(vulnerabilities))
