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

from agent.common import NuvlaBoxCommon
from os import path, stat
from subprocess import run, PIPE, STDOUT
from pydoc import locate


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
                       'status': None,
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
                       'vulnerabilities': None
                       }

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
                "altitude_key": None
            },
            "ipinfo.io": {
                "url": "https://ipinfo.io/json",
                "coordinates_key": "loc",
                "longitude_key": None,
                "latitude_key": None,
                "altitude_key": None
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

    def send_mqtt(self, cpu=None, ram=None, disks=None, energy=None):
        """ Gets the telemetry data and send the stats into the MQTT broker

        :param cpu: tuple (capacity, load)
        :param ram: tuple (capacity, used)
        :param disk: list of {device: partition_name, capacity: value, used: value}
        """

        try:
            self.mqtt_telemetry.connect(self.mqtt_broker_host, self.mqtt_broker_port, self.mqtt_broker_keep_alive)
        except ConnectionRefusedError:
            logging.exception("Connection to NuvlaBox MQTT broker refused")
            self.mqtt_telemetry.disconnect()
            return
        except socket.gaierror:
            logging.exception("The NuvlaBox MQTT broker is not reachable...trying again later")
            self.mqtt_telemetry.disconnect()
            return

        msgs = []
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

    def get_status(self):
        """ Gets several types of information to populate the NuvlaBox status """

        # get status for Nuvla
        disk_usage = self.get_disks_usage()
        operational_status = self.get_operational_status()
        docker_info = self.get_docker_info()

        cpu_sample = {
            "capacity": int(psutil.cpu_count()),
            "load": float(psutil.getloadavg()[2])
        }

        ram_sample = {
            "capacity": int(round(psutil.virtual_memory()[0]/1024/1024)),
            "used": int(round(psutil.virtual_memory()[3]/1024/1024))
        }

        cpu = {"topic": "cpu", "raw-sample": json.dumps(cpu_sample)}
        cpu.update(cpu_sample)

        ram = {"topic": "ram", "raw-sample": json.dumps(ram_sample)}
        ram.update(ram_sample)

        disks = []
        for dsk in disk_usage:
            dsk.update({"topic": "disks", "raw-sample": json.dumps(dsk)})
            disks.append(dsk)

        status_for_nuvla = {
            'resources': {
                'cpu': cpu,
                'ram': ram,
                'disks': disks
            },
            'operating-system': docker_info["OperatingSystem"],
            "architecture": docker_info["Architecture"],
            "hostname": docker_info["Name"],
            "ip": self.get_ip(),
            "docker-server-version": self.docker_client.version()["Version"],
            "last-boot": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": operational_status,
            "nuvlabox-api-endpoint": self.get_nuvlabox_api_endpoint(),
            "docker-plugins": self.get_docker_plugins()
        }

        net_stats = self.get_network_info()
        if net_stats:
            status_for_nuvla['resources']['net-stats'] = net_stats

        power_consumption = None
        try:
            power_consumption = self.get_power_consumption()
            if power_consumption:
                status_for_nuvla['resources']['power-consumption'] = power_consumption
        except:
            logging.exception("Unable to retrieve power consumption metrics")

        if self.gpio_utility:
            # Get GPIO pins status
            gpio_pins = self.get_gpio_pins()

            if gpio_pins:
                status_for_nuvla['gpio-pins'] = gpio_pins

        inferred_location = self.get_ip_geolocation()
        if inferred_location:
            status_for_nuvla['inferred-location'] = inferred_location

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

            status_for_nuvla['vulnerabilities'] = formatted_vulnerabilities

        # set the nb engine version if it exists
        if self.nuvlabox_engine_version:
            status_for_nuvla['nuvlabox-engine-version'] = self.nuvlabox_engine_version

        # Publish the telemetry into the Data Gateway
        self.send_mqtt(cpu_sample, ram_sample, disk_usage, power_consumption)

        # get all status for internal monitoring
        all_status = status_for_nuvla.copy()
        all_status.update({
            "cpu-usage": psutil.cpu_percent(),
            "cpu-load": cpu_sample['load'],
            "disk-usage": psutil.disk_usage("/")[3],
            "memory-usage": psutil.virtual_memory()[2],
            "cpus": cpu_sample['capacity'],
            "memory": ram_sample['capacity'],
            "disk": int(psutil.disk_usage('/')[0]/1024/1024/1024)
        })

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
                return {}

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
                                    output.append([metric_combo[1], mf.read().split()[0], metric_combo[2]])
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
        expected = [{"position": None, "attribute": "BCM", "type": "int"},
                    {"position": None, "attribute": "NAME", "type": "str"},
                    {"position": None, "attribute": "MODE", "type": "str"},
                    {"position": None, "attribute": "VOLTAGE", "type": "int"}]

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
                expected[i]["position"] = indexes[i]

                try:
                    value = locate(exp["type"])
                    cast_value = value(gpio_values[exp["position"]].rstrip().lstrip())

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

    def get_ip_geolocation(self):
        """ Based on a preset of geolocation services, this method tries, one by one, to infer the
        NuvlaBox physical location based on IP

        :returns inferred_location. A list ([longitude, latitude, altitude]). Note that 'altitude' might be missing"""

        now = int(datetime.datetime.timestamp(datetime.datetime.now()))
        try:
            with open(self.ip_geolocation_file) as ipgeof:
                previous_geolocation_json = json.loads(ipgeof.read())

            before = previous_geolocation_json["timestamp"]

            if now - before <= self.time_between_get_geolocation:
                # too soon to infer geolocation
                return None
        except FileNotFoundError:
            logging.debug("Inferring IP-based geolocation for the first time")
        except (json.decoder.JSONDecodeError, KeyError):
            logging.exception("Existing IP-based geolocation is malformed. Inferring again...")
        except:
            logging.exception("Error while preparing to infer IP-based geolocation. Forcing infer operation...")

        inferred_location = []
        for service, service_info in self.ip_geolocation_services.items():
            try:
                logging.debug("Inferring geolocation with 3rd party service %s" % service)
                geolocation = requests.get(service_info['url'], allow_redirects=False).json()
            except:
                logging.exception(f"Could not infer IP-based geolocation from service {service}")
                continue

            try:
                if service_info['coordinates_key']:
                    coordinates = geolocation[service_info['coordinates_key']]
                    # note that Nuvla expects [long, lat], and not [lat, long], thus the reversing
                    if isinstance(coordinates, str):
                        inferred_location = coordinates.split(',')[::-1]
                    elif isinstance(coordinates, list):
                        inferred_location = coordinates[::-1]
                    else:
                        logging.warning(f"Cannot parse coordinates {coordinates} retrieved from geolocation service {service}")
                        continue
                else:
                    longitude = geolocation[service_info['longitude_key']]
                    latitude = geolocation[service_info['latitude_key']]

                    inferred_location.extend([longitude, latitude])
                    if service_info['altitude_key']:
                        inferred_location.append(geolocation[service_info['altitude_key']])

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
            content = {"coordinated": inferred_location, "timestamp": now}
            with open(self.ip_geolocation_file, 'w') as ipgeof:
                ipgeof.write(json.dumps(content))

        return inferred_location

    def get_docker_plugins(self):
        """ Gets the list of all Docker plugins that are installed and enabled

        :returns list of strings (plugin names) """

        all_plugins = self.docker_client.plugins.list()

        enabled_plugins = []
        for plugin in all_plugins:
            if plugin.enabled:
                enabled_plugins.append(plugin.name)

        return enabled_plugins

    def get_docker_info(self):
        """ Invokes the command docker info

        :returns JSON structure with all the Docker informations
        """

        return self.docker_client.info()

    def get_network_info(self):
        """ Gets the list of net ifaces and corresponding rxbytes and txbytes

        :returns {"iface1": {"rx_bytes": X, "tx_bytes": Y}, "iface2": ...}
        """

        sysfs_net = "{}/sys/class/net".format(self.hostfs)

        try:
            ifaces = os.listdir(sysfs_net)
        except FileNotFoundError:
            logging.warning("Cannot find network information for this device")
            return {}

        net_stats = []
        for interface in ifaces:
            stats = "{}/{}/statistics".format(sysfs_net, interface)
            try:
                with open("{}/rx_bytes".format(stats)) as rx:
                    rx_bytes = int(rx.read())
                with open("{}/tx_bytes".format(stats)) as tx:
                    tx_bytes = int(tx.read())
            except FileNotFoundError:
                logging.warning("Cannot calculate net usage for interface {}".format(interface))
                continue

            net_stats.append({
                "interface": interface,
                "bytes-transmitted": tx_bytes,
                "bytes-received": rx_bytes
            })

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

        logging.info(r)
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
                            capacity = round(int(dev['size']/1024/1024/1024))
                            used = round(int(dev['fsused']/1024/1024/1024))
                            output.append({
                                'device': dev['name'],
                                'capacity': capacity,
                                'used': used
                            })
                        except KeyError:
                            logging.exception(f'Unable to get disk usage for mountpoint {dev.get("mountpoint")}')
                            continue

        if output:
            return output
        else:
            return output_fallback

    def diff(self, old_status, new_status):
        """ Compares the previous status with the new one and discover the minimal changes """

        minimal_update = {}
        delete_attributes = []
        for key in self.status.keys():
            if key in new_status:
                if new_status[key] is None:
                    delete_attributes.append(key)
                    continue
                if old_status[key] != new_status[key]:
                    minimal_update[key] = new_status[key]
        return minimal_update, delete_attributes

    def update_status(self):
        """ Runs a cycle of the categorization, to update the NuvlaBox status """

        new_status, all_status = self.get_status()
        updated_status, delete_attributes = self.diff(self.status, new_status)
        updated_status['current-time'] = datetime.datetime.utcnow().isoformat().split('.')[0] + 'Z'
        updated_status['id'] = self.nb_status_id
        logging.info('Refresh status: %s' % updated_status)
        try:
            self.api()._cimi_put(self.nb_status_id,
                             json=updated_status)  # should also include ", select=delete_attributes)" but CIMI does not allow
        except:
            logging.exception("Unable to update NuvlaBox status in Nuvla")
            return None
        finally:
            # write all status into the shared volume for the other components to re-use if necessary
            with open(self.nuvlabox_status_file, 'w') as nbsf:
                nbsf.write(json.dumps(all_status))

        self.status.update(new_status)

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

    def get_nuvlabox_api_endpoint(self):
        """ Double checks that the NuvlaBox API is online

        :returns URL for the NuvlaBox API endpoint
        """

        nb_ext_endpoint = "https://{}:5001/api".format(self.get_ip())
        nb_int_endpoint = "https://management-api:5001/api"

        try:
            requests.get(nb_int_endpoint, verify=False)
        except requests.exceptions.SSLError:
            # the API endpoint exists, we simply did not authenticate
            return nb_ext_endpoint
        except requests.exceptions.ConnectionError:
            return None
        except:
            # let's assume it doesn't exist either
            return None

        return nb_int_endpoint

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
