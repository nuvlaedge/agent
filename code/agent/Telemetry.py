#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Telemetry

It takes care of updating the NuvlaBox status
resource in Nuvla.
"""

import datetime
import docker
import logging
import multiprocessing
import socket

from agent.common import NuvlaBoxCommon
from os import path, stat


class Telemetry(NuvlaBoxCommon.NuvlaBoxCommon):
    """ The Telemetry class, which includes all methods and
    properties necessary to categorize a NuvlaBox and send all
    data into the respective NuvlaBox status at Nuvla

    Attributes:
        data_volume: path to shared NuvlaBox data
    """

    def __init__(self, data_volume, nuvlabox_status_id):
        """ Constructs an Telemetry object, with a status placeholder """

        # self.data_volume = data_volume
        # self.vpn_folder = "{}/vpn".format(data_volume)
        super().__init__(shared_data_volume=data_volume)

        # self.api = nb.ss_api() if not api else api
        self.nb_status_id = nuvlabox_status_id
        self.docker_client = docker.from_env()
        self.status = {'resources': None,
                       'status': None
                       }

    def get_status(self):
        """ Gets several types of information to populate the NuvlaBox status """

        cpu_info = self.get_cpu()
        ram_info = self.get_ram()
        disk_usage = self.get_disks_usage()
        # usb_devices = self.get_usb_devices()
        operational_status = self.get_operational_status()

        return {
            'resources': {
                'cpu': {
                    'capacity': cpu_info[0],
                    'load': cpu_info[1]
                },
                'ram': {
                    'capacity': ram_info[0],
                    'used': ram_info[1]
                },
                'disks': disk_usage
            },
            'status': operational_status
        }

    @staticmethod
    def get_cpu():
        """ Looks up the CPU percentage in use

        :returns Total count of CPUs
        :returns 1-min average load
        """

        try:
            with open("/proc/loadavg", "r") as f:
                averages = f.readline()
                load_average = float(averages.split(' ')[2])
        except:
            load_average = 0.0

        return int(multiprocessing.cpu_count()), load_average

    def get_ram(self):
        """ Looks up the total and used memory available """

        result = self.shell_execute(['/usr/bin/free', '-m'])['stdout'].splitlines()[1].split()
        capacity = int(result[1])
        used = int(result[2])
        return capacity, used

    def get_disk_part_usage(self, partition_path):
        """ Individually looks up disk usage for partition """

        result = self.shell_execute(['df', partition_path])['stdout'].splitlines()[1].split()
        capacity = int(result[1]) // 1024
        used = int(result[2]) // 1024
        return capacity, used

    def get_disks_usage(self):
        """ Gets disk usage for N partitions """

        disk_usage = self.get_disk_part_usage('/')
        return [{'device': 'overlay',
                 'capacity': disk_usage[0],
                 'used': disk_usage[1]
                 }]

    @staticmethod
    def to_json_disks(disks):
        """ Transformation method """

        disks_json = {}
        for disk in disks:
            disks_json[disk[0]] = {'capacity': disk[1], 'used': disk[2]}
        return disks_json

    @staticmethod
    def to_json_usb(usb_devices):
        """ Transformation method """

        usb_devices_json = []
        for usb in usb_devices:
            usb_json = {'bus-id': usb[0],
                        'device-id': usb[1],
                        'vendor-id': usb[2],
                        'product-id': usb[3],
                        'description': usb[4],
                        'busy': usb[5]}
            usb_devices_json.append(usb_json)
        return usb_devices_json

    def diff(self, old_status, new_status):
        """ Compares the previous status with the new one and discover the minimal changes """

        minimal_update = {}
        delete_attributes = []
        for key in self.status.keys():
            if new_status[key] is None:
                delete_attributes.append(key)
                continue
            if old_status[key] != new_status[key]:
                minimal_update[key] = new_status[key]
        return minimal_update, delete_attributes

    def update_status(self):
        """ Runs a cycle of the categorization, to update the NuvlaBox status """

        new_status = self.get_status()
        updated_status, delete_attributes = self.diff(self.status, new_status)
        updated_status['current-time'] = datetime.datetime.utcnow().isoformat().split('.')[0] + 'Z'
        updated_status['id'] = self.nb_status_id
        logging.info('Refresh status: %s' % updated_status)
        self.api()._cimi_put(self.nb_status_id,
                           json=updated_status)  # should also include ", select=delete_attributes)" but CIMI does not allow
        self.status = new_status

    def update_operational_status(self, status="RUNNING", status_log=None):
        """ Update the NuvlaBox status with the current operational status

        :param status: status, according to the allowed set defined in the api server nuvlabox-status schema
        :param status_log: reason for the specified status
        :return:
        """

        new_operational_status = {'status': status}
        if status_log:
            new_operational_status["status-log"] = status_log

        self.api()._cimi_put(self.nb_status_id, json=new_operational_status)

        self.set_local_operational_status(status)

    def get_ip(self):
        """ Discovers the NuvlaBox IP (aka endpoint) """

        # NOTE: This code does not work on Ubuntu 18.04.
        # with open("/proc/self/cgroup", 'r') as f:
        #    docker_id = f.readlines()[0].replace('\n', '').split("/")[-1]

        # Docker sets the hostname to be the short version of the container id.
        # This method of getting the container id works on both Ubuntu 16 and 18.
        docker_id = socket.gethostname()

        deployment_scenario = self.docker_client.containers.get(docker_id).labels["nuvlabox.deployment"]

        if deployment_scenario == "localhost":
            # Get the Docker IP within the shared Docker network

            # ip = self.docker_client.info()["Swarm"]["NodeAddr"]

            ip = socket.gethostbyname(socket.gethostname())
        elif deployment_scenario == "onpremise":
            # Get the local network IP
            # Hint: look at the local Nuvla IP, and scan the host network interfaces for an IP within the same subnet
            # You might need to launch a new container from here, in host mode, just to run `ifconfig`, something like:
            #       docker run --rm --net host alpine ip addr

            # FIXME: Review whether this is the correct impl. for this case.
            ip = self.docker_client.info()["Swarm"]["NodeAddr"]
        elif deployment_scenario == "production":
            # Get either the public IP (via an online service) or use the VPN IP

            if path.exists(self.vpn_ip_file) and stat(self.vpn_ip_file).st_size != 0:
                ip = str(open(self.vpn_ip_file).read().splitlines()[0])
            else:
                ip = self.docker_client.info()["Swarm"]["NodeAddr"]
        else:
            logging.warning("Cannot infer the NuvlaBox IP!")
            return None

        return ip
