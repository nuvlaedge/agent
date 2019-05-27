#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Telemetry

It takes care of updating the NuvlaBox status
resource in Nuvla.
"""

import logging
import docker
import multiprocessing
from agent.common import nuvlabox as nb
import requests_unixsocket


class Telemetry(object):
    """ The Telemetry class, which includes all methods and
    properties necessary to categorize a NuvlaBox and send all
    data into the respective NuvlaBox status at Nuvla

    Attributes:
        data_volume: path to shared NuvlaBox data
    """

    def __init__(self, data_volume, nuvlabox_status_id, api=None):
        """ Constructs an Telemetry object, with a status placeholder """

        self.data_volume = data_volume
        self.api = nb.ss_api() if not api else api
        self.nb_status_id = nuvlabox_status_id
        self.docker_client = docker.from_env()
        self.status = {'resources': None,
                      'peripherals': None,
                      # 'mutableWifiPassword': None,
                      # 'swarmNodeId': None,
                      # 'swarmManagerToken': None,
                      # 'swarmWorkerToken': None,
                      'status': None
                      # 'swarmNode': None,
                      # 'swarmManagerId': None,
                      # 'leader?': None,
                      # 'tlsCA': None,
                      # 'tlsCert': None,
                      # 'tlsKey': None
                      }

    def get_status(self):
        """ Gets several types of information to populate the NuvlaBox status """

        cpu_info = self.get_cpu()
        ram_info = self.get_ram()
        return {
            'resources': {
                'cpu': {
                    'capacity': cpu_info[0],
                    'load': cpu_info[1]
                },
                'ram': {
                    'capacity': ram_info[0] ,
                    'used': ram_info[1]
                },
                'disks': self.get_disks_usage()
            },
            'peripherals': {
                'usb': self.get_usb_devices()
            },
            # 'mutableWifiPassword': nb.nuvlaboxdb.read("psk", db = db_obj),
            # 'swarmNodeId': docker_client.info()['Swarm']['NodeID'],
            # 'swarmManagerId': docker_client.info()['Swarm']['NodeID'],
            # 'swarmManagerToken': docker_client.swarm.attrs['JoinTokens']['Manager'],
            # 'swarmWorkerToken': docker_client.swarm.attrs['JoinTokens']['Worker'],
            'status': nb.get_operational_status(self.data_volume),
            # 'swarmNode': nb.nuvlaboxdb.read("swarm-node", db = db_obj),
            # 'leader?': str(nb.nuvlaboxdb.read("leader", db = db_obj)).lower() == 'true',
            # 'tlsCA': nb.nuvlaboxdb.read("tlsCA", db = db_obj),
            # 'tlsCert': nb.nuvlaboxdb.read("tlsCert", db = db_obj),
            # 'tlsKey': nb.nuvlaboxdb.read("tlsKey", db = db_obj)
        }

    @staticmethod
    def get_cpu():
        """ Looks up the CPU percentage in use

        :returns Total count of CPUs
        :returns 1-min average load
        """

        load_average = float(str(nb.shell_execute(['top', '-p 0', '-bn1'])['stdout'].splitlines()[0]).split(',')[2].split()[-1])
        return int(multiprocessing.cpu_count()), float(load_average)

    @staticmethod
    def get_ram():
        """ Looks up the total and used memory available """

        result = nb.shell_execute(['/usr/bin/free', '-m'])['stdout'].splitlines()[1].split()
        capacity = int(result[1])
        used = int(result[2])
        return capacity, used

    @staticmethod
    def get_disk_part_usage(partition_path):
        """ Individually looks up disk usage for partition """

        result = nb.shell_execute(['df', partition_path])['stdout'].splitlines()[1].split()
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
    def is_usb_busy(bus_id, device_id):
        """ Checks if USB device is busy """

        usb_path = '/dev/bus/usb/{0}/{1}'.format(bus_id, device_id)
        return_code = nb.shell_execute(['/usr/bin/lsof', usb_path])['returncode']
        return return_code == 0

    def get_usb_devices(self):
        """ Looks up list of USB devices """

        usb_devices_line = nb.shell_execute(['/usr/bin/lsusb'])['stdout'].decode("utf-8").splitlines()
        usb_devices = []
        for usb_device in usb_devices_line:
            usb_info = usb_device.split()
            bus_id = usb_info[1]
            device_id = usb_info[3][:3]
            vendor_id = usb_info[5][:4]
            product_id = usb_info[5][5:9]
            description = usb_device[33:]
            usb_devices.append({
                'busy': self.is_usb_busy(bus_id, device_id),
                'vendor-id': vendor_id,
                'device-id': device_id,
                'bus-id': bus_id,
                'product-id': product_id,
                'description': description
            })

        return usb_devices

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

    def update_status(self, next_check):
        """ Runs a cycle of the categorization, to update the NuvlaBox status """

        new_status = self.get_status()
        updated_status, delete_attributes = self.diff(self.status, new_status)
        updated_status['next-heartbeat'] = next_check.isoformat().split('.')[0] + 'Z'
        updated_status['id'] = self.nb_status_id
        logging.info('Refresh status: %s' % updated_status)
        self.api._cimi_put(self.nb_status_id, json=updated_status) # should also include ", select=delete_attributes)" but CIMI does not allow
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

        self.api._cimi_put(self.nb_status_id, json=new_operational_status)

        nb.set_local_operational_status(self.data_volume, status)

    def get_ip(self):
        """ Discovers the NuvlaBox IP (aka endpoint) """

        with open("/proc/self/cgroup", 'r') as f:
            docker_id = f.readlines()[0].replace('\n', '').split("/")[-1]

        deployment_scenario = self.docker_client.containers.get(docker_id).labels["nuvlabox.deployment"]

        if deployment_scenario == "localhost":
            # Get the Docker IP within the shared Docker network
            session = requests_unixsocket.Session()
            r = session.get('http+unix://%2Fvar%2Frun%2Fdocker.sock/nodes')
            if r.status_code == 200:
                ip = r.json()[0]['ManagerStatus']['Addr'].split(':')[0]
            else:
                ip = None
        elif deployment_scenario == "onpremise":
            # Get the local network IP
            # Hint: look at the local Nuvla IP, and scan the host network interfaces for an IP within the same subnet
            # You might need to launch a new container from here, in host mode, just to run `ifconfig`, something like:
            #       docker run --rm --net host alpine ip addr
            ip = "0.0.0.1"  # TODO
        elif deployment_scenario == "production":
            # Get either the public IP (via an online service) or use the VPN IP
            ip = "0.0.0.2"  # TODO
        else:
            logging.warning("Cannot infer the NuvlaBox IP!")
            return None

        return ip



