import os
import shutil
import logging
import argparse
import json
import subprocess
import fcntl, socket, struct
import nuvlaboxdb
from slipstream.api import Api
from subprocess import PIPE, Popen
from contextlib import contextmanager
from tinydb import TinyDB, Query

REMOTES_FILE = '%%NB_REMOTES_FILE%%'
USER_FILE = '/boot/nuvlabox.user'
VPN_FOLDER = '%%NB_VPN_FOLDER%%'
VPN_FILES = {
    "sslCA": "intermediates.crt",
    "sslCert": "nuvlabox.crt",
    "sslKey": "nuvlabox.key"
}

DB, DB_PATH = nuvlaboxdb.init_db()

def get_mac_address(ifname, separator=':'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    mac = separator.join(['%02x' % ord(char) for char in info[18:24]])
    nuvlaboxdb.insert("MAC", ":".join(['%02x' % ord(char) for char in info[18:24]]))
    return mac

try:
    MAC_ADDRESS = get_mac_address('eth0', '')
except IOError:
    with open("/boot/cmdline.txt" , "r") as cmdline:
        MAC_ADDRESS = cmdline.read().splitlines()[0].split("smsc95xx.macaddr=")[1].split()[0].replace(":", "")

NUVLABOX_ID = 'nuvlabox-record/{}'.format(MAC_ADDRESS)
NUVLABOX_STATE_ID = 'nuvlabox-state/{}'.format(MAC_ADDRESS)


def logger(log_level, log_file):
    logging.basicConfig(level=log_level)
    root_logger = logging.getLogger()

    file_handler = logging.FileHandler(log_file)
    root_logger.addHandler(file_handler)

    return root_logger


def arguments(description, default_log_file):
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true')
    parser.add_argument('-q', '--quiet', dest='quiet', default=False, action='store_true')
    parser.add_argument('-l', '--log-filepath', dest='log_file', default=default_log_file, metavar='FILE')

    return parser


def get_log_level(args):
    if args.debug:
        return logging.DEBUG
    elif args.quiet:
        return logging.CRITICAL
    return logging.INFO


def load_remotes():
    remotes = {}
    execfile(REMOTES_FILE, {}, remotes)
    return remotes


def load_user():
    user_info = {}
    execfile(USER_FILE, {}, user_info)
    return user_info


def remount(mount_point, mode):
    subprocess.check_call('mount -o remount,{} {}'.format(mode, mount_point), shell=True)


def find_mount_point(path):
    path = os.path.abspath(path)
    while not os.path.ismount(path):
        path = os.path.dirname(path)
    return path


def is_readonly_fs(mount_point):
    return bool(os.statvfs(mount_point).f_flag & 1)


@contextmanager
def open_ensure_readwrite(filepath, mode):
    mount_point = find_mount_point(filepath)
    is_readonly = is_readonly_fs(mount_point)
    temp_file = filepath + '.temp'

    if is_readonly:
        logging.info('Remounting {} read-write'.format(mount_point))
        remount(mount_point, 'rw')

    with open(temp_file, mode) as f:
        yield f

    shutil.move(temp_file, filepath)
    if is_readonly:
        logging.info('Remounting {} read-only'.format(mount_point))
        remount(mount_point, 'ro')


def shell_execute(cmd):
    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    return {'stdout':stdout, 'stderr':stderr, 'returncode':p.returncode}


def create_user_file(user_info):
    logging.info('Generating user file {}'.format(USER_FILE))

    for k, v in user_info.items():
        if k in ['username', 'password']:
            nuvlaboxdb.insert(k, v)

    with open_ensure_readwrite(USER_FILE, 'w') as f:
        for k, v in user_info.items():
            if k in ['username', 'password']:
                f.write('{}="{}"\n'.format(k, v))

    logging.info('User file generated')


def create_context_file(nuvlabox_info):
    logging.info('Generating context file {}'.format(DB_PATH))

    for k, v in nuvlabox_info.items():
        if k in ['id', 'identifier', 'hwRevisionCode', 'OSVersion', 'sslCA', 'sslCert', 'vpnIP',
                 'sslKey', 'formFactor', 'manufacturerSerialNumber', 'refreshInterval']:
            nuvlaboxdb.insert(k, v)
            if k in ['sslCA', 'sslCert', 'sslKey']:
                vpn_cred_file = "%s/keys/%s" % (VPN_FOLDER, VPN_FILES[k])
                with open(vpn_cred_file, 'w') as vpnf:
                    vpnf.write(v)

                if k == 'sslCA':
                    ca = open("%s/keys/ca.crt" % VPN_FOLDER, 'r')
                    with open("%s/keys/ca-full.crt" % VPN_FOLDER, 'w') as cafull:
                        cafull.write(v+"\n"+ca.read())
                    ca.close()

        elif k in ['connector', 'owner']:
            nuvlaboxdb.insert(k, v['href'])

    logging.info('Context file generated')


def ss_api(remotes=load_remotes()):
    return Api(endpoint='https://{}'.format(remotes['SLIPSTREAM_ENDPOINT']), reauthenticate=True)


def authenticate(api):
    user_info = load_user()
    username = user_info['username']
    logging.info('Authenticate with username "{}"'.format(username))
    api.login_internal(username, user_info['password'])
    return api


def get_nuvlabox_info(api):
    return api.cimi_get(NUVLABOX_ID).json