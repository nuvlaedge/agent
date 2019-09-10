#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox
Common set of methods for the NuvlaBox agent
"""

import os
import json
import logging
import argparse
import fcntl, socket, struct
from nuvla.api import Api
from subprocess import PIPE, Popen

# REMOTES_FILE = '%%NB_REMOTES_FILE%%'
NUVLA_ENDPOINT = os.environ["NUVLA_ENDPOINT"] if "NUVLA_ENDPOINT" in os.environ else "nuvla.io"
NUVLA_ENDPOINT_INSECURE = os.environ["NUVLA_ENDPOINT_INSECURE"] if "NUVLA_ENDPOINT_INSECURE" in os.environ else False
CONTEXT = ".context"

USER_FILE = '/boot/nuvlabox.user'
VPN_FOLDER = '%%NB_VPN_FOLDER%%'
VPN_FILES = {
    "sslCA": "intermediates.crt",
    "sslCert": "nuvlabox.crt",
    "sslKey": "nuvlabox.key"
}


def get_mac_address(ifname, separator=':'):
    """ Gets the MAC address for interface ifname """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
        mac = ':'.join('%02x' % b for b in info[18:24])
        return mac
    except struct.error:
        logging.error("Could not find the device's MAC address from the network interface {} in {}".format(ifname, s))
        raise
    except TypeError:
        logging.error("The MAC address could not be parsed")
        raise


def get_id_from_context(data_volume):
    """ Reads NUVLABOX ID from previous run """

    with open("{}/{}".format(data_volume, CONTEXT)) as cont:
        id = json.loads(cont.read())['id']

    return id


if 'NUVLABOX_UUID' in os.environ and os.environ['NUVLABOX_UUID']:
    NUVLABOX_ID = os.environ['NUVLABOX_UUID']
elif os.path.exists("/srv/nuvlabox/shared/{}".format(CONTEXT)):
    NUVLABOX_ID = get_id_from_context("/srv/nuvlabox/shared")
else:
    NUVLABOX_ID = get_mac_address('eth0', '')

if "nuvlabox/" in NUVLABOX_ID:
    NUVLABOX_RESOURCE_ID = NUVLABOX_ID
else:
    NUVLABOX_RESOURCE_ID = 'nuvlabox/{}'.format(NUVLABOX_ID)

logging.info(NUVLABOX_RESOURCE_ID)


def logger(log_level, log_file):
    """ Configures logging """

    logging.basicConfig(filename=log_file)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # stdout_handler = logging.StreamHandler(sys.stdout)
    # root_logger.addHandler(stdout_handler)

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
    parser.add_argument('-v', '--data-volume', dest='data_volume', default=default_data_volume, metavar='PATH')
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
    """ Writes contextualization file with nuvlabox resource content

    :param nuvlabox_info: nuvlabox resource data
    :param data_volume: where to store it
    """

    context_file = "{}/{}".format(data_volume, CONTEXT)
    logging.info('Generating context file {}'.format(context_file))

    with open(context_file, 'w') as c:
        c.write(json.dumps(nuvlabox_info))


def ss_api():
    """ Returns an Api object """

    return Api(endpoint='https://{}'.format(NUVLA_ENDPOINT), insecure=NUVLA_ENDPOINT_INSECURE, reauthenticate=True)


# def authenticate(api):
#     user_info = load_user()
#     username = user_info['username']
#     logging.info('Authenticate with username "{}"'.format(username))
#     api.login_internal(username, user_info['password'])
#     return api

def authenticate(api, api_key, secret_key):
    """ Creates a user session """

    logging.info('Authenticate with "{}"'.format(api_key))
    logging.info(api.login_apikey(api_key, secret_key))
    return api


def get_nuvlabox_info(api):
    """ Retrieves the respective resource from Nuvla """

    return api._cimi_get(NUVLABOX_RESOURCE_ID)


def get_operational_status(base_dir):
    """ Retrieves the operational status of the NuvlaBox from the .status file """

    try:
        operational_status = open("{}/.status".format(base_dir)).readlines()[0].replace('\n', '').upper()
    except FileNotFoundError:
        logging.warning("Operational status could not be found")
        operational_status = "UNKNOWN"
    except IndexError:
        logging.warning("Operational status has not been correctly set")
        operational_status = "UNKNOWN"
        set_local_operational_status(base_dir, operational_status)

    return operational_status


def set_local_operational_status(base_dir, status):
    """ Write the operational status into the .status file """

    with open("{}/.status".format(base_dir), 'w') as s:
        s.write(status)

