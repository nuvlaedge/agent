#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox
Common set of methods for the NuvlaBox agent
"""

import os
import sys
import json
# import shutil
import logging
import argparse
# import subprocess
import fcntl, socket, struct
# import nuvlaboxdb
from nuvla.api import Api
from subprocess import PIPE, Popen
# from contextlib import contextmanager
# from tinydb import TinyDB, Query

# REMOTES_FILE = '%%NB_REMOTES_FILE%%'
NUVLA_ENDPOINT="nuv.la"

USER_FILE = '/boot/nuvlabox.user'
VPN_FOLDER = '%%NB_VPN_FOLDER%%'
VPN_FILES = {
    "sslCA": "intermediates.crt",
    "sslCert": "nuvlabox.crt",
    "sslKey": "nuvlabox.key"
}

# DB, DB_PATH = nuvlaboxdb.init_db()


def get_mac_address(ifname, separator=':'):
    """ Gets the MAC address for interface ifname """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    mac = separator.join(['%02x' % ord(char) for char in info[18:24]])
    return mac

# try:
#     MAC_ADDRESS = get_mac_address('eth0', '')
# except IOError:
#     with open("/boot/cmdline.txt" , "r") as cmdline:
#         MAC_ADDRESS = cmdline.read().splitlines()[0].split("smsc95xx.macaddr=")[1].split()[0].replace(":", "")

# NUVLABOX_ID = 'nuvlabox-record/{}'.format(MAC_ADDRESS)
# NUVLABOX_STATE_ID = 'nuvlabox-state/{}'.format(MAC_ADDRESS)


NUVLABOX_ID = os.environ['ID'] if 'NUVLABOX_ID' in os.environ else get_mac_address('eth0', '')
NUVLABOX_RECORD_ID = 'nuvlabox-record/{}'.format(NUVLABOX_ID)
NUVLABOX_STATE_ID = 'nuvlabox-state/{}'.format(NUVLABOX_ID)


def logger(log_level, log_file):
    """ Configures logging """

    logging.basicConfig(level=log_level)
    root_logger = logging.getLogger()

    file_handler = logging.FileHandler(log_file)
    root_logger.addHandler(file_handler)

    stdout_handler = logging.StreamHandler(sys.stdout)
    root_logger.addHandler(stdout_handler)

    return root_logger


def arguments(description, default_data_volume, default_log_file):
    """ Builds a generic argparse

    :param description: helper text
    :param default_data_volume: path to shared data volume
    :param default_log_file: name of the log file
    :return: parser
    """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true')
    parser.add_argument('-q', '--quiet', dest='quiet', default=False, action='store_true')
    parser.add_argument('-l', '--log-filepath', dest='log_file',
                        default="{}/{}".format(default_data_volume, default_log_file), metavar='FILE')
    parser.add_argument('-v', '--data-volume', dest='data_volume', default=default_data_volume, action='store_true')
    return parser


def get_log_level(args):
    """ Sets log level based on input args """

    if args.debug:
        return logging.DEBUG
    elif args.quiet:
        return logging.CRITICAL
    return logging.INFO

#
# def load_remotes():
#     remotes = {}
#     execfile(REMOTES_FILE, {}, remotes)
#     return remotes
#
#
# def load_user():
#     user_info = {}
#     execfile(USER_FILE, {}, user_info)
#     return user_info


# def remount(mount_point, mode):
#     subprocess.check_call('mount -o remount,{} {}'.format(mode, mount_point), shell=True)
#
#
# def find_mount_point(path):
#     path = os.path.abspath(path)
#     while not os.path.ismount(path):
#         path = os.path.dirname(path)
#     return path
#
#
# def is_readonly_fs(mount_point):
#     return bool(os.statvfs(mount_point).f_flag & 1)

#
# @contextmanager
# def open_ensure_readwrite(filepath, mode):
#     mount_point = find_mount_point(filepath)
#     is_readonly = is_readonly_fs(mount_point)
#     temp_file = filepath + '.temp'
#
#     if is_readonly:
#         logging.info('Remounting {} read-write'.format(mount_point))
#         remount(mount_point, 'rw')
#
#     with open(temp_file, mode) as f:
#         yield f
#
#     shutil.move(temp_file, filepath)
#     if is_readonly:
#         logging.info('Remounting {} read-only'.format(mount_point))
#         remount(mount_point, 'ro')


def shell_execute(cmd):
    """ Shell wrapper to execute a command

    :param cmd: command to execute
    :return: all outputs
    """

    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    return {'stdout': stdout, 'stderr': stderr, 'returncode': p.returncode}


# def create_user_file(user_info):
#     logging.info('Generating user file {}'.format(USER_FILE))
#
#     for k, v in user_info.items():
#         if k in ['username', 'password']:
#             nuvlaboxdb.insert(k, v)
#
#     with open_ensure_readwrite(USER_FILE, 'w') as f:
#         for k, v in user_info.items():
#             if k in ['username', 'password']:
#                 f.write('{}="{}"\n'.format(k, v))
#
#     logging.info('User file generated')


def create_context_file(nuvlabox_info, data_volume):
    """ Writes contextualization file with nuvlabox_record content

    :param nuvlabox_info: nuvlabox record data
    :param data_volume: where to store it
    """

    context_file = "{}/.context".format(data_volume)
    logging.info('Generating context file {}'.format(context_file))

    with open(context_file, 'w') as c:
        c.write(json.dumps(nuvlabox_info))


def ss_api():
    """ Returns an Api object """

    return Api(endpoint='https://{}'.format(NUVLA_ENDPOINT), reauthenticate=True)


# def authenticate(api):
#     user_info = load_user()
#     username = user_info['username']
#     logging.info('Authenticate with username "{}"'.format(username))
#     api.login_internal(username, user_info['password'])
#     return api

def authenticate(api, username, pwd):
    """ Creates a user session """

    logging.info('Authenticate with username "{}"'.format(username))
    api.login_internal(username, pwd)
    return api


def get_nuvlabox_info(api):
    """ Retrieves the respective resource from Nuvla """

    return api.cimi_get(NUVLABOX_RECORD_ID).json
