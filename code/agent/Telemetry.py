# -*- coding: utf-8 -*-

""" NuvlaBox Telemetry

It takes care of updating the NuvlaBox status
resource in Nuvla.
"""

import datetime
import inspect
import json
import logging
import os
import threading
from typing import Dict

import paho.mqtt.client as mqtt
import psutil
import socket
import time

from os import path, stat

import agent.common.NuvlaBoxCommon as NuvlaBoxCommon
from agent.monitor.edge_status import EdgeStatus
from agent.monitor.components import get_monitor, active_monitors
from agent.monitor import Monitor


class MonitoredDict(dict):
    """
    Subclass of dict that use logging.debug to inform when a change is made.
    """

    def __init__(self, name, *args, **kwargs):
        self.name = name
        dict.__init__(self, *args, **kwargs)
        self._log_caller()
        logging.debug(f'{self.name} __init__: args: {args}, kwargs: {kwargs}')

    def _log_caller(self):
        stack = inspect.stack()
        cls_fn_name = stack[1].function
        caller = stack[2]
        cc = caller.code_context
        code_context = cc[0] if cc and len(cc) >= 1 else ''
        logging.debug(
            f'{self.name}.{cls_fn_name} called by {caller.filename}:{caller.lineno} {caller.function} {code_context}')

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self._log_caller()
        logging.debug(f'{self.name} set {key} = {value}')

    def __repr__(self):
        return '%s(%s)' % (type(self).__name__, dict.__repr__(self))

    def update(self, *args, **kwargs):
        dict.update(self, *args, **kwargs)
        self._log_caller()
        logging.debug(f'{self.name} update: args: {args}, kwargs: {kwargs}')
        logging.debug(f'{self.name} updated: {self}')


class Telemetry(NuvlaBoxCommon.NuvlaBoxCommon):
    """ The Telemetry class, which includes all methods and
    properties necessary to categorize a NuvlaBox and send all
    data into the respective NuvlaBox status at Nuvla

    Attributes:
        data_volume: path to shared NuvlaBox data
    """

    def __init__(self, data_volume, nuvlabox_status_id):
        """ Constructs an Telemetry object, with a status placeholder """

        super(Telemetry, self).__init__(shared_data_volume=data_volume)
        self.logger: logging.Logger = logging.getLogger('Telemetry')
        self.nb_status_id = nuvlabox_status_id
        self.first_net_stats = {}

        self.status_default = {
            'resources': None,
            'status': None,
            'status-notes': None,
            'nuvlabox-api-endpoint': None,
            'operating-system': None,
            'architecture': None,
            'ip': None,
            'last-boot': None,
            'hostname': None,
            'docker-server-version': None,
            'gpio-pins': None,
            'nuvlabox-engine-version': None,
            'inferred-location': None,
            'vulnerabilities': None,
            'node-id': None,
            'cluster-id': None,
            'cluster-managers': None,
            'cluster-nodes': None,
            'cluster-node-role': None,
            'installation-parameters': None,
            'swarm-node-cert-expiry-date': None,
            'host-user-home': None,
            'orchestrator': None,
            'cluster-join-address': None,
            'temperatures': None,
            'container-plugins': None,
            'kubelet-version': None,
            'current-time': '',
            'id': None,
            'components': None
        }
        self._status = MonitoredDict('Telemetry.status', self.status_default.copy())
        self._status_on_nuvla = MonitoredDict('Telemetry.status_on_nuvla')

        self.mqtt_telemetry = mqtt.Client()

        self.edge_status: EdgeStatus = EdgeStatus()

        self.monitor_list: list[Monitor] = []
        self.initialize_monitors()

    def initialize_monitors(self):
        """
        Auxiliary function to extract some control from the class initialization
        It gathers the available monitors and initializes them saving the reference into
        the monitor_list attribute of Telemtry
        """
        for x in active_monitors:
            self.monitor_list.append(get_monitor(x)(x, self, True))
        self.logger.info(f'Monitors initializer: {[x.name for x in self.monitor_list]}')

    @property
    def status_on_nuvla(self):
        return self._status_on_nuvla

    @status_on_nuvla.setter
    def status_on_nuvla(self, value):
        self._status_on_nuvla = MonitoredDict('Telemetry.status_on_nuvla', value)
        caller = inspect.stack()[1]
        logging.debug(f'Telemetry.status_on_nuvla setter called by {caller.filename}:'
                      f'{caller.lineno} {caller.function} {caller.code_context}')
        logging.debug(f'Telemetry.status_on_nuvla updated: {value}')

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = MonitoredDict('Telemetry.status', value)
        caller = inspect.stack()[1]
        logging.debug(f'Telemetry.status setter called by '
                      f'{caller.filename}:{caller.lineno} {caller.function} {caller.code_context}')
        logging.debug(f'Telemetry.status updated: {value}')

    def send_mqtt(self, nuvlabox_status, cpu=None, ram=None, disks=None, energy=None):
        """ Gets the telemetry data and send the stats into the MQTT broker

        :param nuvlabox_status: full dump of the NB status {}
        :param cpu: tuple (capacity, load)
        :param ram: tuple (capacity, used)
        :param disks: list of {device: partition_name, capacity: value, used: value}
        :param energy: energy consumption metric
        """

        try:
            self.mqtt_telemetry.connect(self.mqtt_broker_host, self.mqtt_broker_port, self.mqtt_broker_keep_alive)
        except ConnectionRefusedError:
            logging.warning("Connection to NuvlaBox MQTT broker refused")
            self.mqtt_telemetry.disconnect()
            return
        except socket.timeout:
            logging.warning(f'Timed out while trying to send telemetry to Data Gateway at {self.mqtt_broker_host}')
            return
        except socket.gaierror:
            logging.warning("The NuvlaBox MQTT broker is not reachable...trying again later")
            self.mqtt_telemetry.disconnect()
            return

        os.system("mosquitto_pub -h {} -t {} -m '{}'".format(self.mqtt_broker_host,
                                                             "nuvlabox-status",
                                                             json.dumps(nuvlabox_status)))

        if cpu:
            # e1 = self.mqtt_telemetry.publish("cpu/capacity", payload=str(cpu[0]))
            # e2 = self.mqtt_telemetry.publish("cpu/load", payload=str(cpu[1]))
            # ISSUE: for some reason, the connection is lost after publishing with paho-mqtt

            # using os.system for now

            os.system("mosquitto_pub -h {} -t {} -m '{}'".format(self.mqtt_broker_host,
                                                                 "cpu",
                                                                 json.dumps(cpu)))

        if ram:
            # self.mqtt_telemetry.publish("ram/capacity", payload=str(ram[0]))
            # self.mqtt_telemetry.publish("ram/used", payload=str(ram[1]))
            # same issue as above
            os.system("mosquitto_pub -h {} -t {} -m '{}'".format(self.mqtt_broker_host,
                                                                 "ram",
                                                                 json.dumps(ram)))

        if disks:
            for dsk in disks:
                # self.mqtt_telemetry.publish("disks", payload=json.dumps(dsk))
                # same issue as above
                os.system("mosquitto_pub -h {} -t {} -m '{}'".format(self.mqtt_broker_host,
                                                                     "disks",
                                                                     json.dumps(dsk)))

        if energy:
            # self.mqtt_telemetry.publish("ram/capacity", payload=str(ram[0]))
            # self.mqtt_telemetry.publish("ram/used", payload=str(ram[1]))
            # same issue as above
            os.system("mosquitto_pub -h {} -t {} -m '{}'".format(self.mqtt_broker_host,
                                                                 "energy",
                                                                 json.dumps(energy)))

        # self.mqtt_telemetry.disconnect()

    def set_status_operational_status(self, body: dict, node: dict):
        """
        Gets and sets the operational status and status_notes for the nuvlabox-status

        :param body: payload for the nuvlabox-status update request
        :param node: information about the underlying COE node
        """
        operational_status_notes = self.get_operational_status_notes()
        operational_status = self.get_operational_status()

        system_errors, system_warnings = self.container_runtime.read_system_issues(node)

        operational_status_notes += system_errors + system_warnings
        if system_errors:
            operational_status = 'DEGRADED'

        if not self.installation_home:
            operational_status_notes.append(
                "HOST_HOME not defined - SSH key management will not be functional")

        body.update({
            "status": operational_status,
            "status-notes": operational_status_notes,
        })

    def get_status(self):
        """ Gets several types of information to populate the NuvlaBox status """

        status_for_nuvla = self.status_default.copy()
        monitor_process_time: Dict = {}

        for it_monitor in self.monitor_list:
            if it_monitor.is_thread and not it_monitor.is_alive():

                if it_monitor.ident:
                    it_monitor.join()
                    logging.error(
                        f'Current number of threads: {len(threading.enumerate())}')
                else:
                    logging.error(f'Starting thread {it_monitor.name} for first time')
                    it_monitor.start()
            else:
                if not it_monitor.is_thread or not it_monitor.is_alive():
                    init_time: float = time.time()

                    it_monitor.update_data()
                    monitor_process_time[it_monitor.name] = time.time() - init_time

        self.logger.info(f'Monitors processing time '
                         f'{json.dumps(monitor_process_time, indent=4)}')

        for it_monitor in self.monitor_list:
            it_monitor.populate_nb_report(status_for_nuvla)

        node_info = self.container_runtime.get_node_info()
        # - STATUS attrs
        self.set_status_operational_status(status_for_nuvla, node_info)

        # - CURRENT TIME attr
        status_for_nuvla['current-time'] = datetime.datetime.utcnow().isoformat().split('.')[0] + 'Z'

        # Publish the telemetry into the Data Gateway
        self.send_mqtt(
            status_for_nuvla,
            status_for_nuvla.get('resources', {}).get('cpu', {}).get('raw-sample'),
            status_for_nuvla.get('resources', {}).get('ram', {}).get('raw-sample'),
            status_for_nuvla.get('resources', {}).get('disks', []))

        # get all status for internal monitoring
        all_status = status_for_nuvla.copy()
        all_status.update({
            "cpu-usage": psutil.cpu_percent(),
            "cpu-load": status_for_nuvla.get('resources', {}).get('cpu', {}).get('load'),
            "disk-usage": psutil.disk_usage("/")[3],
            "memory-usage": psutil.virtual_memory()[2],
            "cpus": status_for_nuvla.get('resources', {}).get('cpu', {}).get('capacity'),
            "memory": status_for_nuvla.get('resources', {}).get('ram', {}).get('capacity'),
            "disk": int(psutil.disk_usage('/')[0] / 1024 / 1024 / 1024)
        })
        # logging.error(json.dumps(status_for_nuvla, indent=4))
        return status_for_nuvla, all_status

    @staticmethod
    def diff(previous_status, current_status):
        """
        Compares the previous status with the new one and discover the minimal changes
        """

        items_changed_or_added = {}
        attributes_to_delete = set(previous_status.keys()) - set(current_status.keys())

        for key, value in current_status.items():
            if value is None:
                attributes_to_delete.add(key)
            elif value != previous_status.get(key):
                items_changed_or_added[key] = value

        return items_changed_or_added, attributes_to_delete

    def update_status(self):
        """ Runs a cycle of the categorization, to update the NuvlaBox status """

        new_status, all_status = self.get_status()

        # write all status into the shared volume for the other
        # components to re-use if necessary
        with open(self.nuvlabox_status_file, 'w') as nbsf:
            nbsf.write(json.dumps(all_status))

        self.status.update(new_status)

    def get_vpn_ip(self):
        """ Discovers the NuvlaBox VPN IP  """

        if path.exists(self.vpn_ip_file) and stat(self.vpn_ip_file).st_size != 0:
            ip = str(open(self.vpn_ip_file).read().splitlines()[0])
        else:
            logging.warning("Cannot infer the NuvlaBox VPN IP!")
            return None

        return ip
