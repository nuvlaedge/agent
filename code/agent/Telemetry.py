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
import paho.mqtt.client as mqtt
import psutil
import queue
import re
import requests
import socket
import time

from docker.errors import APIError
from os import path, stat
from subprocess import run, PIPE, STDOUT
from threading import Thread

import agent.common.NuvlaBoxCommon as NuvlaBoxCommon
import agent.monitor.components.network as net_monitor
from agent.monitor.edge_status import EdgeStatus
from agent.monitor.components import get_monitor, monitors
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


class ContainerMonitoring(Thread):
    """ A special thread used to asynchronously fetch the stats from all containers in the system

    Attributes:
        q: queue object where to put the monitoring results (JSON)
        save_to: an optional string pointing to a file where to persist the JSON output
        log: a logging object
    """

    def __init__(self, q: queue.Queue, cr: NuvlaBoxCommon.ContainerRuntimeClient,
                 save_to: str = None, log: logging = logging):
        Thread.__init__(self)
        self.q = q
        self.save_to = save_to
        self.container_runtime = cr
        self.log = log

    def run(self):
        """
        Runs, on an infinite loop, through all the containers in the system and retrieves the stats for each one,
        saving them in a file (if needed), and putting them in a messaging queue for other processes in the system
        to fetch

        :return:
        """

        while True:
            out = self.container_runtime.collect_container_metrics()
            self.q.put(out)

            if self.save_to:
                with open(self.save_to, 'w') as f:
                    f.write(json.dumps(out))

            time.sleep(10)


class Telemetry(NuvlaBoxCommon.NuvlaBoxCommon):
    """ The Telemetry class, which includes all methods and
    properties necessary to categorize a NuvlaBox and send all
    data into the respective NuvlaBox status at Nuvla

    Attributes:
        data_volume: path to shared NuvlaBox data
    """

    def __init__(self, data_volume, nuvlabox_status_id, enable_container_monitoring=True):
        """ Constructs an Telemetry object, with a status placeholder """

        super(Telemetry, self).__init__(shared_data_volume=data_volume)
        # NuvlaBoxCommon.NuvlaBoxCommon.__init__(self, shared_data_volume=data_volume)

        self.nb_status_id = nuvlabox_status_id
        self.first_net_stats = {}
        self.container_stats_queue = queue.Queue()
        self.enable_container_monitoring = enable_container_monitoring
        if enable_container_monitoring:
            self.container_stats_monitor = ContainerMonitoring(self.container_stats_queue,
                                                               self.container_runtime,
                                                               self.container_stats_json_file)
            self.container_stats_monitor.daemon = True
            self.container_stats_monitor.start()

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

        self.gpio_utility = False
        try:
            r = run(['gpio', '-v'], stdout=PIPE)
            self.gpio_utility = True
        except:
            # no need to catch any exception. This is just a quick check and fail for the GPIO utility
            pass

        self.ip_geolocation_services = {
            "ip-api.com": {
                "url": "http://ip-api.com/json/",
                "coordinates_key": None,
                "longitude_key": "lon",
                "latitude_key": "lat",
                "altitude_key": None,
                "ip": "query"
            },
            "ipinfo.io": {
                "url": "https://ipinfo.io/json",
                "coordinates_key": "loc",
                "longitude_key": None,
                "latitude_key": None,
                "altitude_key": None,
                "ip": "ip"
            },
            "ipapi.co": {
                "url": "https://ipapi.co/json",
                "coordinates_key": None,
                "longitude_key": "longitude",
                "latitude_key": "latitude",
                "altitude_key": None
            },
            "ipgeolocation.com": {
                "url": "https://ipgeolocation.com/?json=1",
                "coordinates_key": "coords",
                "longitude_key": None,
                "latitude_key": None,
                "altitude_key": None
            }
        }

        # Minimum interval, in seconds, for inferring IP-based geolocation
        # (to avoid network jittering and 3rd party service spamming)
        # Default to 1 hour
        self.time_between_get_geolocation = 3600

        self.edge_status: EdgeStatus = EdgeStatus()
        # TODO: IP Gathering tests
        self.monitor_list: list[Monitor] = []

        # TODO: Fix proper initialization
        for x in monitors:
            self.monitor_list.append(get_monitor(x)(x, self, True))

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

    def get_installation_parameters(self):
        """ Retrieves the configurations and parameteres used during the NuvlaBox Engine installation

        :return: obj - {project-name: str, config-files: list, working-dir: str}
        """

        filter_label = "nuvlabox.component=True"

        return self.container_runtime.get_installation_parameters(filter_label)

    def get_swarm_node_cert_expiration_date(self):
        """ If the docker swarm certs can be found, try to infer their expiration date

        :return:
        """

        if os.path.exists(self.swarm_node_cert):
            command = ["openssl", "x509", "-enddate", "-noout", "-in", self.swarm_node_cert]
            output = run(command, stdout=PIPE, stderr=STDOUT, encoding='UTF-8')
            # example output: 'notAfter=Mar 12 19:13:00 2021 GMT\n'
            if output.returncode != 0 or not output.stdout:
                return None

            expiry_date_raw = output.stdout.strip().split('=')[-1]
            raw_format = '%b %d %H:%M:%S %Y %Z'
            return datetime.datetime.strptime(expiry_date_raw, raw_format).strftime(self.nuvla_timestamp_format)

        else:
            return None

    def set_status_resources(self, body: dict):
        """
        Set the information about disk usage in the NuvlaBox status paylod

        Args:
            body (dict): NuvlaBox Status payload
        """
        # DISK
        disk_usage = self.get_disks_usage()
        disks = []
        for dsk in disk_usage:
            dsk.update({"topic": "disks", "raw-sample": json.dumps(dsk)})
            disks.append(dsk)

        # CPU
        cpu_sample = {
            "capacity": int(psutil.cpu_count()),
            "load": float(psutil.getloadavg()[2]),
            "load-1": float(psutil.getloadavg()[0]),
            "load-5": float(psutil.getloadavg()[1]),
            "context-switches": int(psutil.cpu_stats().ctx_switches),
            "interrupts": int(psutil.cpu_stats().interrupts),
            "software-interrupts": int(psutil.cpu_stats().soft_interrupts),
            "system-calls": int(psutil.cpu_stats().syscalls)
        }
        cpu = {"topic": "cpu", "raw-sample": json.dumps(cpu_sample)}
        cpu.update(cpu_sample)

        # MEMORY
        ram_sample = {
            "capacity": int(round(psutil.virtual_memory()[0] / 1024 / 1024)),
            "used": int(round(psutil.virtual_memory()[3] / 1024 / 1024))
        }
        ram = {"topic": "ram", "raw-sample": json.dumps(ram_sample)}
        ram.update(ram_sample)

        # DOCKER STATS
        # container_stats = None
        # try:
        #     container_stats = self.container_stats_queue.get(block=False)
        # except queue.Empty:
        #     if not self.container_stats_monitor.is_alive() and self.enable_container_monitoring:
        #         self.container_stats_monitor = ContainerMonitoring(self.container_stats_queue,
        #                                                            self.container_runtime,
        #                                                            self.container_stats_json_file)
        #         self.container_stats_monitor.daemon = True
        #         self.container_stats_monitor.start()

        # NETWORK
        net_stats = self.get_network_info()

        # POWER
        try:
            power_consumption = self.get_power_consumption()
        except Exception as e:
            logging.error(f"Unable to retrieve power consumption metrics: {str(e)}")
            power_consumption = None

        ###
        resources = {
            'cpu': cpu,
            'ram': ram
        }

        conditional_resources = [
            ('disks', disks),
            # ('container-stats', container_stats),
            ('net-stats', net_stats),
            ('power-consumption', power_consumption)
        ]
        for cres in conditional_resources:
            if cres[1]:
                resources[cres[0]] = cres[1]

        body['resources'] = resources

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

        # status_for_nuvla['id'] = self.nb_status_id
        for it_monitor in self.monitor_list:
            if it_monitor.is_thread and not it_monitor.is_alive():
                logging.error(f'Starting monitor {it_monitor.name}')
                it_monitor.start()
            else:
                init_time: float = time.time()
                it_monitor.update_data()
                logging.error(f'Monitor {it_monitor.name} process time '
                              f'{time.time() - init_time}')

        for it_monitor in self.monitor_list:
            it_monitor.populate_nb_report(status_for_nuvla)

        node_info = self.container_runtime.get_node_info()

        # get status for Nuvla
        # - RESOURCES attr
        # self.set_status_resources(status_for_nuvla)

        # - STATUS attrs
        self.set_status_operational_status(status_for_nuvla, node_info)

        # - COE VERSIONS attrs
        # self.set_status_coe_version(status_for_nuvla)

        # - CLUSTER attrs
        # self.set_status_cluster(status_for_nuvla, node_info)

        # - INSTALLATION PARAMETERS attr
        # self.set_status_installation_params(status_for_nuvla)

        # - COE CERT EXPIRATION attr
        # self.set_status_coe_cert_expiration_date(status_for_nuvla)

        # - TEMPERATURES attr
        # self.set_status_temperatures(status_for_nuvla)

        # - GPIO PINS attr
        # self.set_status_gpio(status_for_nuvla)

        # - LOCATION attr
        # self.set_status_inferred_location(status_for_nuvla)

        # - VULNERABILITIES attr
        # self.set_status_vulnerabilities(status_for_nuvla)

        # - COMPONENTS attr
        # self.set_status_components(status_for_nuvla)

        # - CURRENT TIME attr
        status_for_nuvla['current-time'] = datetime.datetime.utcnow().isoformat().split('.')[0] + 'Z'

        # Publish the telemetry into the Data Gateway
        self.send_mqtt(status_for_nuvla,
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
        logging.error(json.dumps(status_for_nuvla, indent=4))
        return status_for_nuvla, all_status

    def get_power_consumption(self):
        """ Attempts to retrieve power monitoring information, if it exists. It is highly dependant on the
        underlying host system and the existence of a power monitoring drive/device. Thus this is optional
        telemetry data.

        :return: list of well-defined metric-consumption-units lists. Example: [["metric", "consumption", "unit"], ... ]
        """

        output = []
        # for the NVIDIA Jetson ...
        for driver in self.nvidia_software_power_consumption_model:
            i2c_fs_path = f'{self.hostfs}/sys/bus/i2c/drivers/{driver}'

            if not os.path.exists(i2c_fs_path):
                return []

            i2c_addresses_found = \
                [addr for addr in os.listdir(i2c_fs_path) if re.match(r"[0-9]-[0-9][0-9][0-9][0-9]", addr)]
            i2c_addresses_found.sort()
            channels = self.nvidia_software_power_consumption_model[driver]['channels']
            for nvidia_board, power_info in self.nvidia_software_power_consumption_model[driver]['boards'].items():
                known_i2c_addresses = power_info['i2c_addresses']
                known_i2c_addresses.sort()
                if i2c_addresses_found != known_i2c_addresses:
                    continue

                for metrics_folder_name in power_info['channels_path']:
                    metrics_folder_path = f'{i2c_fs_path}/{metrics_folder_name}'
                    if not os.path.exists(metrics_folder_path):
                        continue

                    for channel in range(0, channels):
                        rail_name_file = f'{metrics_folder_path}/rail_name_{channel}'
                        if not os.path.exists(rail_name_file):
                            continue

                        with open(rail_name_file) as m:
                            try:
                                metric_basename = m.read().split()[0]
                            except:
                                logging.warning(f'Cannot read power metric rail name at {rail_name_file}')
                                continue

                        rail_current_file = f'{metrics_folder_path}/in_current{channel}_input'
                        rail_voltage_file = f'{metrics_folder_path}/in_voltage{channel}_input'
                        rail_power_file = f'{metrics_folder_path}/in_power{channel}_input'
                        rail_critical_current_limit_file = f'{metrics_folder_path}/crit_current_limit_{channel}'

                        # (filename, metric name, units)
                        desired_metrics_files = [
                            (rail_current_file, f"{metric_basename}_current", "mA"),
                            (rail_voltage_file, f"{metric_basename}_voltage", "mV"),
                            (rail_power_file, f"{metric_basename}_power", "mW"),
                            (rail_critical_current_limit_file, f"{metric_basename}_critical_current_limit", "mA")
                        ]

                        existing_metrics = os.listdir(metrics_folder_path)

                        if not all(desired_metric[0].split('/')[-1] in
                                   existing_metrics for desired_metric in desired_metrics_files):
                            # one or more power metric files we need, are missing from the directory, skip them
                            continue

                        for metric_combo in desired_metrics_files:
                            try:
                                with open(metric_combo[0]) as mf:
                                    output.append({
                                        "metric-name": metric_combo[1],
                                        "energy-consumption": float(mf.read().split()[0]),
                                        "unit": metric_combo[2]
                                    })
                            except:
                                continue

        return output

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
