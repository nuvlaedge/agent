#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Telemetry

It takes care of updating the NuvlaBox state
resource in Nuvla.
"""

# import socket
import logging
import docker
# import datetime
# import os
from agent.common import nuvlabox as nb


# LOG_FILE = '/var/log/nuvlabox-agent.log'

class Telemetry(object):
    """ The Telemetry class, which includes all methods and
    properties necessary to categorize a NuvlaBox and send all
    data into the respective NuvlaBox state at Nuvla

    Attributes:
        data_volume: path to shared NuvlaBox data
    """

    def __init__(self, data_volume, api=None):
        """ Constructs an Telemetry object, with a state placeholder """

        self.data_volume = data_volume
        self.api = nb.ss_api() if not api else api
        self.state = {'cpu': -1,
                      'ram': (0, 0),
                      'disks': set([]),
                      'usb': set([]),
                      # 'mutableWifiPassword': None,
                      'swarmNodeId': None,
                      'swarmManagerToken': None,
                      'swarmWorkerToken': None,
                      # 'swarmNode': None,
                      # 'swarmManagerId': None,
                      # 'leader?': None,
                      # 'tlsCA': None,
                      # 'tlsCert': None,
                      # 'tlsKey': None
                      }

    def get_state(self):
        """ Gets several types of information to populate the NuvlaBox state """

        docker_client = docker.from_env()
        return {'cpu': self.get_cpu(),
                'ram': self.get_ram(),
                'disks': self.get_disks_usage(),
                'usb': self.get_usb_devices(),
                # 'mutableWifiPassword': nb.nuvlaboxdb.read("psk", db = db_obj),
                'swarmNodeId': docker_client.info()['Swarm']['NodeID'],
                # 'swarmManagerId': docker_client.info()['Swarm']['NodeID'],
                'swarmManagerToken': docker_client.swarm.attrs['JoinTokens']['Manager'],
                'swarmWorkerToken': docker_client.swarm.attrs['JoinTokens']['Worker'],
                # 'swarmNode': nb.nuvlaboxdb.read("swarm-node", db = db_obj),
                # 'leader?': str(nb.nuvlaboxdb.read("leader", db = db_obj)).lower() == 'true',
                # 'tlsCA': nb.nuvlaboxdb.read("tlsCA", db = db_obj),
                # 'tlsCert': nb.nuvlaboxdb.read("tlsCert", db = db_obj),
                # 'tlsKey': nb.nuvlaboxdb.read("tlsKey", db = db_obj)
                }

    @staticmethod
    def get_cpu():
        """ Looks up the CPU percentage in use """

        idle = float(str(nb.shell_execute(['top', '-p 0', '-bn1'])['stdout'].splitlines()[2]).split(',')[3].split()[0])
        cpu_percentage = int(round(100 - idle))
        return cpu_percentage

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

        return {('overlay',) + self.get_disk_part_usage('/')}

    @staticmethod
    def is_usb_busy(bus_id, device_id):
        """ Checks if USB device is busy """

        usb_path = '/dev/bus/usb/{0}/{1}'.format(bus_id, device_id)
        return_code = nb.shell_execute(['/usr/bin/lsof', usb_path])['returncode']
        return return_code == 0

    def get_usb_devices(self):
        """ Looks up list of USB devices """

        usb_devices_line = nb.shell_execute(['/usr/bin/lsusb'])['stdout'].decode("utf-8").splitlines()
        usb_devices = set([])
        for usb_device in usb_devices_line:
            usb_info = usb_device.split()
            bus_id = usb_info[1]
            device_id = usb_info[3][:3]
            vendor_id = usb_info[5][:4]
            product_id = usb_info[5][5:9]
            description = usb_device[33:]
            usb_devices.add((bus_id, device_id, vendor_id, product_id, description,
                             self.is_usb_busy(bus_id, device_id)))
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

    def diff(self, old_state, new_state):
        """ Compares the previous state with the new one and discover the minimal changes """

        minimal_update = {}
        delete_attributes = []
        for key in self.state.keys():
            if new_state[key] is None:
                delete_attributes.append(key)
                continue
            if old_state[key] != new_state[key]:
                if key == "ram":
                    minimal_update['ram'] = {'capacity': new_state['ram'][0], 'used': new_state['ram'][1]}
                elif key == "disks":
                    minimal_update['disks'] = self.to_json_disks(new_state['disks'])
                elif key == "usb":
                    minimal_update['usb'] = self.to_json_usb(new_state['usb'])
                else:
                    minimal_update[key] = new_state[key]
        return minimal_update, delete_attributes

    def udpate_state(self, next_check):
        """ Runs a cycle of the categorization, to update the NuvlaBox state """

        new_state = self.get_state()
        updated_state, delete_attributes = self.diff(self.state, new_state)
        updated_state['nextCheck'] = next_check.isoformat() + 'Z'
        updated_state['nuvlabox'] = {"href": nb.NUVLABOX_RECORD_ID}
        updated_state['id'] = nb.NUVLABOX_STATE_ID
        logging.info('Refresh state: %s' % updated_state)
        self.api.cimi_edit(nb.NUVLABOX_STATE_ID, updated_state) # should also include ", select=delete_attributes)" but CIMI does not allow
        self.state = new_state
