#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" NuvlaBox Telemetry

It takes care of updating the NuvlaBox status
resource in Nuvla.
"""

import datetime
import docker
import logging
import socket
import json
import os
import psutil
import re
import requests
import paho.mqtt.client as mqtt
import queue
import time
import inspect

from agent.common import NuvlaBoxCommon
from os import path, stat
from subprocess import run, PIPE, STDOUT
from threading import Thread
from agent.monitor.IPAddressMonitor import IPAddressTelemetry, NetworkTelemetryStructure


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
        logging.debug(f'{self.name}.{cls_fn_name} called by {caller.filename}:{caller.lineno} {caller.function} {code_context}')

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self._log_caller()
        logging.debug(f'{self.name} set {key} = {value}')

    def __repr__(self):
        return '%s(%s)' % (type(self).__name__,  dict.__repr__(self))

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

        # TODO: IP Gathering tests
        self.network_monitor: IPAddressTelemetry = IPAddressTelemetry(self.vpn_ip_file,
                                                                      self.container_runtime)

    @property
    def status_on_nuvla(self):
        return self._status_on_nuvla

    @status_on_nuvla.setter
    def status_on_nuvla(self, value):
        self._status_on_nuvla = MonitoredDict('Telemetry.status_on_nuvla', value)
        caller = inspect.stack()[1]
        logging.debug(f'Telemetry.status_on_nuvla setter called by {caller.filename}:{caller.lineno} {caller.function} {caller.code_context}')
        logging.debug(f'Telemetry.status_on_nuvla updated: {value}')

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = MonitoredDict('Telemetry.status', value)
        caller = inspect.stack()[1]
        logging.debug(f'Telemetry.status setter called by {caller.filename}:{caller.lineno} {caller.function} {caller.code_context}')
        logging.debug(f'Telemetry.status updated: {value}')

    def send_mqtt(self, nuvlabox_status, cpu=None, ram=None, disks=None, energy=None):
        """ Gets the telemetry data and send the stats into the MQTT broker

        :param nuvlabox_status: full dump of the NB status {}
        :param cpu: tuple (capacity, load)
        :param ram: tuple (capacity, used)
        :param disk: list of {device: partition_name, capacity: value, used: value}
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
            "capacity": int(round(psutil.virtual_memory()[0]/1024/1024)),
            "used": int(round(psutil.virtual_memory()[3]/1024/1024))
        }
        ram = {"topic": "ram", "raw-sample": json.dumps(ram_sample)}
        ram.update(ram_sample)

        # DOCKER STATS
        container_stats = None
        try:
            container_stats = self.container_stats_queue.get(block=False)
        except queue.Empty:
            if not self.container_stats_monitor.is_alive() and self.enable_container_monitoring:
                self.container_stats_monitor = ContainerMonitoring(self.container_stats_queue,
                                                                self.container_runtime,
                                                                self.container_stats_json_file)
                self.container_stats_monitor.setDaemon(True)
                self.container_stats_monitor.start()

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
            ('container-stats', container_stats),
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
            operational_status_notes.append("HOST_HOME not defined - SSH key management will not be functional")

        body.update({
            "status": operational_status,
            "status-notes": operational_status_notes,
        })

    def set_status_ip(self, body: dict):
        """
        Set the IP of the NuvlaBox for the telemetry update

        :param body: payload for the nuvlabox-status update request
        """
        self.network_monitor.update_data()

        ip = self.get_vpn_ip()
        body["ip"] = self.network_monitor.get_data()
        logging.error(body["ip"])
        # body["ip"] = ip if ip else self.container_runtime.get_api_ip_port()[0]

    def set_status_coe_version(self, body: dict):
        """
        Set the version of Docker and Kubelet when possible and if present

        :param body: payload for the nuvlabox-status update request
        """
        docker_server_version = self.get_docker_server_version()
        if docker_server_version:
            body['docker-server-version'] = docker_server_version

        try:
            kubelet_version = self.container_runtime.get_kubelet_version()
            if kubelet_version:
                body['kubelet-version'] = kubelet_version
        except (NameError, AttributeError):
            # method not implemented - meaning this is a Docker installation. Just ignore it
            pass

    def get_cluster_manager_attrs(self, managers: list, node_id: str) -> tuple:
        """
        If this node is a manager, tries to get the WHOLE list of nodes in the cluster

        :param managers: existing cluster managers
        :param node_id: this node's ID
        :return: tuple of (bool, list), to say if this node is a manager, and the whole list of cluster nodes
        """
        cluster_nodes = []
        if node_id not in managers:
            return False, cluster_nodes

        try:
            all_cluster_nodes = self.container_runtime.list_nodes()
        except docker.errors.APIError as e:
            logging.error(f'Cannot get Docker cluster nodes: {str(e)}')
        else:
            for node in all_cluster_nodes:
                active_node_id = self.container_runtime.is_node_active(node)
                if not active_node_id:
                    continue
                if active_node_id not in cluster_nodes:
                    try:
                        cluster_nodes.append(node.id)
                    except AttributeError:
                        continue

            return True, cluster_nodes
        return False, []

    def set_status_cluster(self, body: dict, node: dict):
        """
        Gets and sets all the cluster attributes for the nuvlabox-status

        :param body: payload for the nuvlabox-status update request
        :param node: information about the underlying COE node
        """

        node_id = self.container_runtime.get_node_id(node)
        cluster_id = self.container_runtime.get_cluster_id(node, f'cluster_{self.nuvlabox_id}')
        cluster_managers = self.container_runtime.get_cluster_managers()

        if node_id:
            body["node-id"] = node_id
            body["orchestrator"] = NuvlaBoxCommon.ORCHESTRATOR_COE
            # assume it's a worker to begin with
            body["cluster-node-role"] = "worker"

        if cluster_id:
            body["cluster-id"] = cluster_id

        if cluster_managers:
            body["cluster-managers"] = cluster_managers
            if node_id:
                cluster_join_addr = self.container_runtime.get_cluster_join_address(node_id)
                if cluster_join_addr:
                    body["cluster-join-address"] = cluster_join_addr

        is_manager, cluster_nodes = self.get_cluster_manager_attrs(cluster_managers, node_id)
        if is_manager:
            body["cluster-node-role"] = "manager"

        if len(cluster_nodes) > 0:
            body['cluster-nodes'] = cluster_nodes

    def set_status_installation_params(self, body: dict):
        """
        Sets the NuvlaBox installation parameters attribute in the nuvlabox-status

        :param body: payload for the nuvlabox-status update request
        """
        installation_params = self.get_installation_parameters()
        if installation_params:
            body['installation-parameters'] = installation_params

    def set_status_coe_cert_expiration_date(self, body: dict):
        """
        Sets the COE certificate expiration date in the NuvlaBox Status

        :param body: payload for the nuvlabox-status update request
        """
        if NuvlaBoxCommon.ORCHESTRATOR == 'docker':
            # can only infer this for Docker, cause for K8s, the certificates might be on different folders,
            # depending on the installation tool (k0s vs k3s vs kubeadm ...)
            try:
                swarm_cert_expiration = self.get_swarm_node_cert_expiration_date()
                if swarm_cert_expiration:
                    body['swarm-node-cert-expiry-date'] = swarm_cert_expiration
            except Exception as e:
                logging.warning(f"Cannot infer Docker Swarm cert expiration date. Reason: {str(e)}")

    def set_status_temperatures(self, body: dict):
        """
        Sets the device temperates in the NuvlaBox Status

        :param body: payload for the nuvlabox-status update request
        """
        temperatures = self.get_temperature()
        if temperatures:
            body['temperatures'] = temperatures

    def set_status_gpio(self, body: dict):
        """
        Sets the GPIO pins information in the NuvlaBox Status

        :param body: payload for the nuvlabox-status update request
        """
        if self.gpio_utility:
            # Get GPIO pins status
            gpio_pins = self.get_gpio_pins()
            if gpio_pins:
                body['gpio-pins'] = gpio_pins

    def set_status_inferred_location(self, body: dict):
        """
        Sets the inferred location of the NuvlaBox, in the NuvlaBox Status

        :param body: payload for the nuvlabox-status update request
        """
        inferred_location = self.get_ip_geolocation()
        if inferred_location:
            body['inferred-location'] = inferred_location

    def set_status_vulnerabilities(self, body: dict):
        """
        Sets the vulnerabilities of the NuvlaBox, in the NuvlaBox Status

        :param body: payload for the nuvlabox-status update request
        """
        # get results from security scans
        vulnerabilities = self.get_security_vulnerabilities()
        if vulnerabilities is not None:
            scores = list(filter((-1).__ne__, map(lambda v: v.get('vulnerability-score', -1), vulnerabilities)))
            formatted_vulnerabilities = {
                'summary': {
                    'total': len(vulnerabilities),
                    'affected-products': list(set(map(lambda v: v.get('product', 'unknown'), vulnerabilities)))
                },
                'items': sorted(vulnerabilities, key=lambda v: v.get('vulnerability-score', 0), reverse=True)[0:100]
            }

            if len(scores) > 0:
                formatted_vulnerabilities['summary']['average-score'] = round(sum(scores) / len(scores), 2)

            body['vulnerabilities'] = formatted_vulnerabilities

    def set_status_components(self, body: dict):
        """
        Sets the name of the NuvlaBox components currently installed in the edge device

        :param body: payload for the nuvlabox-status update request
        """
        components = self.container_runtime.get_all_nuvlabox_components()
        if components:
            body['components'] = components

    def get_status(self):
        """ Gets several types of information to populate the NuvlaBox status """

        status_for_nuvla = self.status_default.copy()

        status_for_nuvla['id'] = self.nb_status_id

        node_info = self.container_runtime.get_node_info()
        status_for_nuvla.update({
            'operating-system': self.container_runtime.get_host_os(),
            "architecture": self.container_runtime.get_host_architecture(node_info),
            "hostname": self.container_runtime.get_hostname(node_info),
            "last-boot": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "container-plugins": self.container_runtime.get_container_plugins()
        })
        if self.installation_home:
            status_for_nuvla['host-user-home'] = self.installation_home
        # set the nb engine version if it exists
        if self.nuvlabox_engine_version:
            status_for_nuvla['nuvlabox-engine-version'] = self.nuvlabox_engine_version

        # get status for Nuvla
        # - RESOURCES attr
        self.set_status_resources(status_for_nuvla)

        # - STATUS attrs
        self.set_status_operational_status(status_for_nuvla, node_info)

        # - IP attr
        self.set_status_ip(status_for_nuvla)

        # - COE VERSIONS attrs
        self.set_status_coe_version(status_for_nuvla)

        # - CLUSTER attrs
        self.set_status_cluster(status_for_nuvla, node_info)

        # - INSTALLATION PARAMETERS attr
        self.set_status_installation_params(status_for_nuvla)

        # - COE CERT EXPIRATION attr
        self.set_status_coe_cert_expiration_date(status_for_nuvla)

        # - TEMPERATURES attr
        self.set_status_temperatures(status_for_nuvla)

        # - GPIO PINS attr
        self.set_status_gpio(status_for_nuvla)

        # - LOCATION attr
        self.set_status_inferred_location(status_for_nuvla)

        # - VULNERABILITIES attr
        self.set_status_vulnerabilities(status_for_nuvla)

        # - COMPONENTS attr
        self.set_status_components(status_for_nuvla)

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
            "disk": int(psutil.disk_usage('/')[0]/1024/1024/1024)
        })

        return status_for_nuvla, all_status

    def get_docker_server_version(self):
        try:
            return self.container_runtime.client.version()["Version"]
        except:
            return None

    def get_temperature(self):
        """ Attempts to retrieve temperature information, if it exists. The keys will vary depending on the
        underlying host system.

        :return: JSON with temperatures values for each Thermal Zone founded.
        Example: [{"thermal-zone": "acpitz", "value": <float in Celsius> for x86_64}]
        """

        output = []

        thermal_fs_path = f'{self.hostfs}/sys/devices/virtual/thermal'

        if not os.path.exists(thermal_fs_path):
            return psutil.sensors_temperatures() if hasattr(psutil, 'sensors_temperature') else output

        all_dirs = os.listdir(thermal_fs_path)
        temp_dirs = list(filter(lambda x: x.startswith('thermal'), all_dirs))

        for subdirs in temp_dirs:
            thermal_zone_file = f'{thermal_fs_path}/{subdirs}/type'
            temperature_file = f'{thermal_fs_path}/{subdirs}/temp'
            if not os.path.exists(thermal_zone_file) or not os.path.exists(temperature_file):
                logging.warning(f'Thermal zone (at {thermal_zone_file}) and temperature (at {temperature_file}) values do not complement each other')
                continue

            metric_basename, temperature_value = self.read_temperature_files(thermal_zone_file, temperature_file)

            if not metric_basename or not temperature_value:
                logging.warning(f'Thermal zone {thermal_zone_file} or temperature {temperature_file} value is missing')
                continue

            try:
                output.append({
                    "thermal-zone": metric_basename,
                    "value": float(temperature_value)/1000})
            except (ValueError, TypeError) as e:
                logging.warning(f'Cannot convert temperature at {temperature_file}. Reason: {str(e)}')

        return output

    @staticmethod
    def read_temperature_files(thermal_zone_file_path: str, temperature_file_path: str) -> tuple:
        """
        Reads files, extract temperature/thermal values and returns them

        :param thermal_zone_file_path: path to thermal_zone_file
        :param temperature_file_path: path to temperature_file
        :return: (metric_basename, temperature_value)
        """
        with open(thermal_zone_file_path) as tzf:
            try:
                metric_basename = tzf.read().split()[0]
            except:
                logging.warning(f'Cannot read thermal zone at {thermal_zone_file_path}')
                metric_basename = None

        with open(temperature_file_path) as tf:
            try:
                temperature_value = tf.read().split()[0]
            except:
                logging.warning(f'Cannot read temperature at {temperature_file_path}')
                temperature_value = None

        return metric_basename, temperature_value

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

            i2c_addresses_found = [ addr for addr in os.listdir(i2c_fs_path) if re.match(r"[0-9]-[0-9][0-9][0-9][0-9]", addr) ]
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

                        # (filename, metricname, units)
                        desired_metrics_files = [
                            (rail_current_file, f"{metric_basename}_current", "mA"),
                            (rail_voltage_file, f"{metric_basename}_voltage", "mV"),
                            (rail_power_file, f"{metric_basename}_power", "mW"),
                            (rail_critical_current_limit_file, f"{metric_basename}_critical_current_limit", "mA")
                        ]

                        existing_metrics = os.listdir(metrics_folder_path)

                        if not all(desired_metric[0].split('/')[-1] in existing_metrics for desired_metric in desired_metrics_files):
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

    def get_security_vulnerabilities(self):
        """ Reads vulnerabilities from the security scans, from a file in the shared volume

        :return: contents of the file
        """

        if os.path.exists(self.vulnerabilities_file):
            with open(self.vulnerabilities_file) as vf:
                return json.loads(vf.read())
        else:
            return None

    @staticmethod
    def parse_gpio_pin_cell(indexes, line):
        """ Parses one cell of the output from gpio readall, which has 2 pins

        :param indexes: the index numbers for the values of BCM, Name, Mode, V and Physical (in this order)

        :returns a GPIO dict obj with the parsed pin"""

        # the expected list of attributes is
        expected = [{"position": None, "type": int, "attribute": "BCM"},
                    {"position": None, "type": str, "attribute": "NAME"},
                    {"position": None, "type": str, "attribute": "MODE"},
                    {"position": None, "type": int, "attribute": "VOLTAGE"}]

        needed_indexes_len = 5

        if len(indexes) < needed_indexes_len:
            logging.error(f"Missing indexes needed to parse GPIO pin: {indexes}. Need {needed_indexes_len}")
            return None

        gpio_values = line.split('|')
        gpio_pin = {}
        try:
            gpio_pin['pin'] = int(gpio_values[indexes[-1]])
            # if we can get the physical pin, we can move on. Pin is the only mandatory attr

            for i, exp in enumerate(expected):
                try:
                    cast_value = exp["type"](gpio_values[indexes[i]].rstrip().lstrip())

                    if cast_value or cast_value == 0:
                        gpio_pin[exp["attribute"].lower()] = cast_value
                    else:
                        continue
                except ValueError:
                    logging.debug(f"No suitable {exp['attribute']} value for pin {gpio_pin['pin']}")
                    continue

            return gpio_pin
        except ValueError:
            logging.warning(f"Unable to get GPIO pin status on {gpio_values}, index {indexes[-1]}")
            return None
        except:
            # if there's any other issue while doing so, it means the provided argument is not valid
            logging.exception(f"Invalid list of indexes {indexes} for GPIO pin in {line}. Cannot parse this pin")
            return None

    def get_gpio_pins(self):
        """ Uses the GPIO utility to scan and get the current status of all GPIO pins in the device.
        It then parses the output and gives back a list of pins

        :returns list of JSONs, i.e. [{pin: 1, name: GPIO. 1, bcm: 4, mode: IN}, {pin: 7, voltage: 0, mode: ALT1}]"""

        command = ["gpio", "readall"]
        gpio_out = run(command, stdout=PIPE, stderr=STDOUT, encoding='UTF-8')

        if gpio_out.returncode != 0 or not gpio_out.stdout:
            return None

        trimmed_gpio_out = gpio_out.stdout.splitlines()[3:-3]

        formatted_gpio_status = []
        for gpio_line in trimmed_gpio_out:

            # each line has two columns = 2 pins

            first_pin_indexes = [1, 3, 4, 5, 6]
            second_pin_indexes = [14, 11, 10, 9, 8]
            first_pin = self.parse_gpio_pin_cell(first_pin_indexes, gpio_line)
            if first_pin:
                formatted_gpio_status.append(first_pin)

            second_pin = self.parse_gpio_pin_cell(second_pin_indexes, gpio_line)
            if second_pin:
                formatted_gpio_status.append(second_pin)

        return formatted_gpio_status

    def reuse_previous_geolocation(self, time_now: int) -> dict:
        """
        Checks, based on the time elapsed since the last retrieval, if new geolocation must be inferred

        :param time_now: current timestamp, used to calculate the time elapsed since the last location retrieval
        :return: previous geolocation if there's no need to infer again. None otherwise
        """
        try:
            with open(self.ip_geolocation_file) as ipgeof:
                previous_geolocation_json = json.loads(ipgeof.read())

            before = previous_geolocation_json["timestamp"]

            if time_now - before <= self.time_between_get_geolocation:
                # too soon to infer geolocation
                return previous_geolocation_json.get("coordinates")
        except FileNotFoundError:
            logging.debug("Inferring IP-based geolocation for the first time")
        except (json.decoder.JSONDecodeError, KeyError):
            logging.exception("Existing IP-based geolocation is malformed. Inferring again...")
        except:
            logging.exception("Error while preparing to infer IP-based geolocation. Forcing infer operation...")

    @staticmethod
    def parse_geolocation(ip_location_service_name: str, ip_location_service_info: dict,
                          geolocation_response: dict) -> list:
        """
        Gets the output from the IP-based geolocation request made to the online service, parses it, and builds
        the inferred location, as a list, for the NuvlaBox Status

        :param ip_location_service_name: name of the online service used to get the location
        :param ip_location_service_info: info about the service queried for retrieving the location
                                        (as in self.ip_geolocation_services.items)
        :param geolocation_response: response from the IP-based geolocation service, in JSON format

        :return: inferred-location attribute
        """
        inferred_location = []
        if ip_location_service_info['coordinates_key']:
            coordinates = geolocation_response[ip_location_service_info['coordinates_key']]
            # note that Nuvla expects [long, lat], and not [lat, long], thus the reversing
            if isinstance(coordinates, str):
                inferred_location = coordinates.split(',')[::-1]
            elif isinstance(coordinates, list):
                inferred_location = coordinates[::-1]
            else:
                logging.warning(f"Cannot parse coordinates {coordinates} retrieved from geolocation service {ip_location_service_name}")
                raise TypeError
        else:
            longitude = geolocation_response[ip_location_service_info['longitude_key']]
            latitude = geolocation_response[ip_location_service_info['latitude_key']]

            inferred_location.extend([longitude, latitude])
            if ip_location_service_info['altitude_key']:
                inferred_location.append(geolocation_response[ip_location_service_info['altitude_key']])

        return inferred_location

    def get_ip_geolocation(self):
        """ Based on a preset of geolocation services, this method tries, one by one, to infer the
        NuvlaBox physical location based on IP

        :returns inferred_location. A list ([longitude, latitude, altitude]). Note that 'altitude' might be missing
        """
        now = int(datetime.datetime.timestamp(datetime.datetime.now()))

        previous_coordinates = self.reuse_previous_geolocation(now)
        if previous_coordinates:
            return previous_coordinates

        inferred_location = []
        for service, service_info in self.ip_geolocation_services.items():
            try:
                logging.debug("Inferring geolocation with 3rd party service %s" % service)
                geolocation = requests.get(service_info['url'], allow_redirects=False).json()
            except:
                logging.exception(f"Could not infer IP-based geolocation from service {service}")
                continue

            try:
                inferred_location.extend(self.parse_geolocation(service, service_info, geolocation))
                # if we got here, then we already have coordinates, no need for further queries
                break
            except KeyError:
                logging.exception(f"Cannot get coordination from geolocation JSON {geolocation}, with service {service}")
                continue
            except:
                logging.exception(f"Error while parsing geolocation from {service}")
                continue

        if inferred_location:
            # we have valid coordinates, so let's keep a local record of it
            content = {"coordinates": inferred_location, "timestamp": now}
            with open(self.ip_geolocation_file, 'w') as ipgeof:
                ipgeof.write(json.dumps(content))

        return inferred_location

    def get_network_info(self):
        """ Gets the list of net ifaces and corresponding rxbytes and txbytes

        :returns [{"interface": "iface1", "bytes-transmitted": X, "bytes-received": Y}, {"interface": "iface2", ...}]
        """

        sysfs_net = "{}/sys/class/net".format(self.hostfs)

        try:
            ifaces = os.listdir(sysfs_net)
        except FileNotFoundError:
            logging.warning("Cannot find network information for this device")
            return []

        previous_net_stats = {}
        try:
            with open(self.previous_net_stats_file) as pns:
                previous_net_stats = json.loads(pns.read())
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            pass

        net_stats = []
        for interface in ifaces:
            stats = "{}/{}/statistics".format(sysfs_net, interface)
            try:
                with open("{}/rx_bytes".format(stats)) as rx:
                    rx_bytes = int(rx.read())
                with open("{}/tx_bytes".format(stats)) as tx:
                    tx_bytes = int(tx.read())
            except (FileNotFoundError, NotADirectoryError):
                logging.warning("Cannot calculate net usage for interface {}".format(interface))
                continue

            # we compute the net stats since the beginning of the NB lifetime
            # and our counters reset on every NB restart
            if interface in self.first_net_stats:
                if rx_bytes < self.first_net_stats[interface].get('bytes-received', 0) or \
                        tx_bytes < self.first_net_stats[interface].get('bytes-transmitted', 0):
                    # then the system counters were reset
                    logging.warning(f'Host network counters seem to have been reset for network interface {interface}')
                    if interface in previous_net_stats:
                        # in this case, because the numbers no longer correlate, we need to add up to the previous
                        # reported value
                        rx_bytes_report = previous_net_stats[interface].get('bytes-received', 0) + rx_bytes
                        tx_bytes_report = previous_net_stats[interface].get('bytes-transmitted', 0) + tx_bytes
                    else:
                        rx_bytes_report = rx_bytes
                        tx_bytes_report = tx_bytes

                    self.first_net_stats[interface] = {
                        "bytes-transmitted": tx_bytes,
                        "bytes-received": rx_bytes,
                        "bytes-transmitted-carry": previous_net_stats.get(interface, {}).get('bytes-transmitted', 0),
                        "bytes-received-carry": previous_net_stats.get(interface, {}).get('bytes-received', 0),
                    }
                else:
                    # then counters are still going. In this case we just need to do
                    #
                    # current - first + carry
                    rx_bytes_report = rx_bytes - \
                                        self.first_net_stats[interface].get('bytes-received', 0) + \
                                        self.first_net_stats[interface].get('bytes-received-carry', 0)
                    tx_bytes_report = tx_bytes - \
                                        self.first_net_stats[interface].get('bytes-transmitted', 0) + \
                                        self.first_net_stats[interface].get('bytes-transmitted-carry', 0)
            else:
                rx_bytes_report = previous_net_stats.get(interface, {}).get('bytes-received', 0)
                tx_bytes_report = previous_net_stats.get(interface, {}).get('bytes-transmitted', 0)

                self.first_net_stats[interface] = {
                    "bytes-transmitted": tx_bytes,
                    "bytes-received": rx_bytes,
                    "bytes-transmitted-carry": tx_bytes_report,
                    "bytes-received-carry": rx_bytes_report
                }

            previous_net_stats[interface] = {
                "bytes-transmitted": tx_bytes_report,
                "bytes-received": rx_bytes_report
            }

            net_stats.append({
                "interface": interface,
                "bytes-transmitted": tx_bytes_report,
                "bytes-received": rx_bytes_report
            })

        with open(self.previous_net_stats_file, 'w') as pns:
            pns.write(json.dumps(previous_net_stats))

        return net_stats

    @staticmethod
    def get_disks_usage():
        """ Gets disk usage for N partitions """

        output = []
        output_fallback = [{'device': 'overlay',
                            'capacity': int(psutil.disk_usage('/')[0]/1024/1024/1024),
                            'used': int(psutil.disk_usage('/')[1]/1024/1024/1024)
                            }]

        lsblk_command = ["lsblk", "--json", "-o", "NAME,SIZE,MOUNTPOINT,FSUSED", "-b", "-a"]
        r = run(lsblk_command, stdout=PIPE, stderr=STDOUT, encoding='UTF-8')

        if r.returncode != 0 or not r.stdout:
            return output_fallback

        lsblk = json.loads(r.stdout)
        for blockdevice, devices in lsblk.items():
            for parent_dev in devices:
                flattened = [parent_dev]
                if parent_dev.get('children'):
                    flattened += parent_dev['children']

                for dev in flattened:
                    if dev.get('mountpoint'):
                        # means it is mounted, so we can get its usage
                        try:
                            capacity = round(int(dev['size'])/1024/1024/1024)

                            # TODO: delete this condition once the Nuvla server starts accepting float values
                            if capacity <= 0:
                                continue

                            fused = dev['fsused'] if dev.get('fsused') else "0"
                            used = round(int(fused)/1024/1024/1024)
                            output.append({
                                'device': dev['name'],
                                'capacity': capacity,
                                'used': used
                            })
                        except (KeyError, TypeError):
                            logging.exception(f'Unable to get disk usage for mountpoint {dev.get("mountpoint")}')
                            continue

        if output:
            return output

        return output_fallback

    @staticmethod
    def diff(previous_status, current_status):
        """ Compares the previous status with the new one and discover the minimal changes """

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

        # write all status into the shared volume for the other components to re-use if necessary
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
