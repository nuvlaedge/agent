#!/usr/local/bin/python
# -*- coding: utf-8 -*-

"""NuvlaBox Agent service

This service takes care of the NuvlaBox activation and subsequent
resource discovery and categorization within the hosting device.

It is also responsible for all telemetry data sent to Nuvla.

Arguments:
:param d/debug: (optional) log level set to DEBUG
:param q/quiet: (optional) log level set to CRITICAL
:param l/log_filepath: (optional) path to the log file
:param v/volume: (optional) shared volume where all NuvlaBox data can be found
"""

import copy
import socket
import threading
import json
import logging
import sys
import agent.AgentApi as AgentApi
import requests
import time
from flask import Flask, request, jsonify, Response
from agent.common import NuvlaBoxCommon
from agent.Activate import Activate
from agent.Telemetry import Telemetry
from agent.Infrastructure import Infrastructure
from agent.Job import Job
from threading import Event

__copyright__ = "Copyright (C) 2019 SixSq"
__email__ = "support@sixsq.com"

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

app = Flask(__name__)
data_volume = "/srv/nuvlabox/shared"
default_log_filename = "agent.log"
network_timeout = 10


def manage_pull_jobs(job_list, job_image_name):
    """
    Handles the pull jobs one by one, sequentially

    :param job_list: list of job IDs
    :param job_image_name: Docker Image to be used for the job-engine
    """
    for job_id in job_list:
        job = Job(data_volume, job_id, job_image_name)
        if job.do_nothing:
            continue

        try:
            job.launch()
        except Exception as ex:
            # catch all
            logging.error(f'Cannot process job {job_id}. Reason: {str(ex)}')


def preflight_check(activation_class_object: Activate, infra_class_object: Infrastructure, nb_updated_date: str):
    """
    Checks if the NuvlaBox resource has been updated in Nuvla
    :param activation_class_object: instance of Activate
    :param infra_class_object: instance of Infrastructure
    :param nb_updated_date: date of the last NB resource update
    :return:
    """
    nuvlabox_resource = activation_class_object.get_nuvlabox_info()

    global refresh_interval
    global can_continue
    global nuvlabox_info_updated_date

    if nuvlabox_resource.get('state', '').startswith('DECOMMISSION'):
        logging.warning(f'This NuvlaBox is {nuvlabox_resource["state"]} in Nuvla. Exiting...')
        can_continue = False

    if nb_updated_date != nuvlabox_resource['updated'] and can_continue:
        refresh_interval = nuvlabox_resource['refresh-interval']
        logging.warning('NuvlaBox resource updated. Refresh interval value: {}s'.format(refresh_interval))
        nuvlabox_info_updated_date = nuvlabox_resource['updated']
        activation_class_object.create_nb_document_file(nuvlabox_resource)

    # if there's a mention to the VPN server, then watch the VPN credential
    if nuvlabox_resource.get("vpn-server-id"):
        infra_class_object.watch_vpn_credential(nuvlabox_resource.get("vpn-server-id"))


@app.route('/api/status')
def set_status():
    """ API endpoint to let other components set the NuvlaBox status """

    value = request.args.get('value')
    log = str(request.args.get('log'))

    if not value:
        logging.warning("Received status request with no value. Nothing to do")
    else:
        logging.info("Setting NuvlaBox status to {}".format(value))
        if log:
            print(app.config["telemetry"], dir(app.config["telemetry"]))

    logging.warning('to be implemented')
    return "to be implemented"


@app.route('/api/find-data-gateway')
def find_data_gateway():
    """
    Returns 200 or 404, depending on whether the data-gateway is reachable or not

    :return: 200 or 404
    """

    try:
        socket.gethostbyname('data-gateway')
        return jsonify('success'), 200
    except socket.gaierror as e:
        return jsonify(str(e)), 404


@app.route('/api/commission', methods=['POST'])
def trigger_commission():
    """ API endpoint to let other components trigger a commissioning

    The request.data is the payload
    """

    payload = json.loads(request.data)

    logging.info('Commission triggered via the NB Agent API with payload: %s ' % payload)

    commissioning_response = app.config["infra"].do_commission(payload)
    return jsonify(commissioning_response)


@app.route('/api/set-vulnerabilities', methods=['POST'])
def set_vulnerabilities():
    """ API endpoint to let other components send and save the scanned vulnerabilities

    The request.data is the payload
    """

    payload = json.loads(request.data)

    logging.info('Saving vulnerabilities received via the API: %s ' % payload)

    AgentApi.save_vulnerabilities(payload)

    return jsonify(True), 201


@app.route('/api/set-vpn-ip', methods=['POST'])
def set_vpn_ip():
    """ API endpoint to let other components define the NB VPN IP
    """

    payload = request.data

    logging.info('Received request to set VPN IP to %s ' % payload)

    AgentApi.save_vpn_ip(payload)
    return jsonify(True), 201


@app.route('/api/healthcheck', methods=['GET'])
def healthcheck():
    """ Static endpoint just for clients to check if API/Agent is up and running
    """

    return jsonify(True)


@app.route('/api/agent-container-id', methods=['GET'])
def get_agent_container_id():
    """ Static endpoint just for clients to get the Agent container Docker ID
    """

    return jsonify(socket.gethostname())


@app.route('/api/peripheral', defaults={'identifier': None}, methods=['POST', 'GET'])
@app.route('/api/peripheral/<path:identifier>', methods=['GET', 'PUT', 'DELETE'])
def manage_peripheral(identifier):
    """ API endpoint to let other components manage NuvlaBox peripherals

    :param identifier: local id of the peripheral to be managed
    """

    logging.info('  ####   Received %s request for peripheral management' % request.method)

    payload = {}
    if request.data:
        try:
            payload = json.loads(request.data)
        except:
            return jsonify({"error": "Payload {} malformed. It must be a JSON payload".format(payload)}), 400

    if identifier:
        logging.info('  ####   %s peripheral %s' % (request.method, identifier))
        if request.method in ["DELETE", "PUT"]:
            # DELETE accepts resource ID for simplicity and backward compatibility
            resource_id = request.args.get('id')
            message, return_code = AgentApi.modify(identifier, peripheral_nuvla_id=resource_id,
                                                   action=request.method, payload=payload)
        elif request.method == "GET":
            message, return_code = AgentApi.get(identifier)
        else:
            logging.info('  ####   Method %s not implemented yet!!' % request.method)
            message = "Not implemented"
            return_code = 501
    else:
        # POST or FIND peripheral
        if request.method == "POST":
            logging.info('  ####   Creating new peripheral with payload %s' % payload)
            message, return_code = AgentApi.post(payload)
        else:
            # GET
            parameter = request.args.get('parameter')
            value = request.args.get('value')
            identifier_pattern = request.args.get('identifier_pattern')
            logging.info('  ####   Find peripherals with {}={}'.format(parameter, value))
            message, return_code = AgentApi.find(parameter, value, identifier_pattern)

    return jsonify(message), return_code


def send_heartbeat(nb_instance, nb_telemetry, nb_status_id: str, previous_status_time: str):
    """
    Updates the NuvlaBox Status according to the local status file
    :param nb_instance: instance of class NuvlaBoxCommon.NuvlaBoxCommon()
    :param nb_telemetry: instance of class Telemetry()
    :param nb_status_id: ID of the NB status resource
    :param previous_status_time: ISO timestamp of the previous status heartbeat
    :return: (Nuvla.api response, current heartbeat timestamp)
    """

    status = {}
    telemetry_status = copy.deepcopy(nb_telemetry.status_for_nuvla)
    status_current_time = telemetry_status.get('current-time', '')

    if not status_current_time:
        status = {'status-notes': ['NuvlaBox Telemetry is starting']}
    else:
        if status_current_time <= previous_status_time:
            status = {
                'status-notes': telemetry_status.get('status-notes', []) + ['NuvlaBox telemetry is falling behind'],
                'status': telemetry_status.get('status', 'DEGRADED')
            }

    if status:
        nb_telemetry.status.update(status)
        try:
            r = nb_instance.api().edit(nb_status_id, data=status)
            return status_current_time, r.data
        except:
            logging.error("Unable to update NuvlaBox status in Nuvla")
            raise

    return status_current_time, None


def wait_for_api_ready():
    """
    Waits in a loop for the API to be ready
    :return:
    """
    while True:
        try:
            r = requests.get('http://localhost/api/healthcheck')
            r.raise_for_status()
            if r.status_code == 200:
                break
        except:
            time.sleep(1)

    logging.info('NuvlaBox Agent has been initialized.')
    return


if __name__ == "__main__":
    socket.setdefaulttimeout(network_timeout)

    e = Event()
    # Try to activate the NuvlaBox
    activation = Activate(data_volume)
    logging.info(f'Nuvla endpoint: {activation.nuvla_endpoint}')
    logging.info(f'Nuvla connection insecure: {str(activation.nuvla_endpoint_insecure)}')
    while True:
        can_activate, user_info = activation.activation_is_possible()
        if can_activate or user_info:
            break

        e.wait(timeout=3)

    if not user_info:
        # this NuvlaBox hasn't been activated yet
        user_info = activation.activate()

    nuvlabox_status_id = activation.update_nuvlabox_resource()

    telemetry = Telemetry(data_volume, nuvlabox_status_id)
    infra = Infrastructure(data_volume)
    NB = NuvlaBoxCommon.NuvlaBoxCommon()

    if not infra.installation_home:
        logging.error('Host user HOME directory not defined. This might impact future SSH management actions')
    else:
        with open(infra.host_user_home_file, 'w') as userhome:
            userhome.write(infra.installation_home)
        infra.set_immutable_ssh_key()

    nuvlabox_info_updated_date = ''
    refresh_interval = 5

    app.config["telemetry"] = telemetry
    app.config["infra"] = infra

    api_thread = threading.Thread(target=app.run, kwargs={"host": "0.0.0.0", "port": "80"})
    api_thread.daemon = True
    api_thread.start()

    telemetry_thread = None

    can_continue = True
    nb_checker = None

    past_status_time = ''

    # start telemetry
    with NuvlaBoxCommon.timeout(10):
        logging.info('Waiting for API to be ready...')
        wait_for_api_ready()

    logging.info("Starting telemetry...")
    while True:
        if not can_continue:
            break

        if not nb_checker or not nb_checker.is_alive():
            nb_checker = threading.Thread(target=preflight_check,
                                          args=(activation, infra, nuvlabox_info_updated_date,),
                                          daemon=True)
            nb_checker.start()

        start_cycle = time.time()

        if not telemetry_thread or not telemetry_thread.is_alive():
            telemetry_thread = threading.Thread(target=telemetry.update_status,
                                                args=(NB, nuvlabox_status_id),
                                                daemon=True)
            telemetry_thread.start()

        past_status_time, response = send_heartbeat(NB, telemetry, nuvlabox_status_id, past_status_time)

        jobs = copy.deepcopy(telemetry.jobs)
        if infra.container_runtime.job_engine_lite_image and jobs:
            logging.info(f'Processing the following jobs in pull-mode: {jobs}')
            threading.Thread(target=manage_pull_jobs,
                             args=(jobs, infra.container_runtime.job_engine_lite_image,),
                             daemon=True).start()

        if not infra.is_alive():
            infra = Infrastructure(data_volume, refresh_period=refresh_interval)
            infra.start()

        end_cycle = time.time()
        cycle_duration = end_cycle - start_cycle
        # formula is R-2T, where
        next_cycle_in = refresh_interval - 2 * cycle_duration

        e.wait(timeout=next_cycle_in)
