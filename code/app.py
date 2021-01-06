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

import socket
import threading
import json
import agent.AgentApi as AgentApi
from flask import Flask, request, jsonify, Response
from agent.common import NuvlaBoxCommon
from agent.Activate import Activate
from agent.Telemetry import Telemetry
from agent.Infrastructure import Infrastructure
from threading import Event

__copyright__ = "Copyright (C) 2019 SixSq"
__email__ = "support@sixsq.com"

app = Flask(__name__)
data_volume = "/srv/nuvlabox/shared"
default_log_filename = "agent.log"
network_timeout = 10


def init():
    """ Initialize the application, including argparsing """

    params = NuvlaBoxCommon.arguments().parse_args()

    logger = NuvlaBoxCommon.logger(NuvlaBoxCommon.get_log_level(params))

    return logger, params


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


@app.route('/api/commission', methods=['POST'])
def trigger_commission():
    """ API endpoint to let other components trigger a commissioning

    The request.data is the payload
    """

    payload = json.loads(request.data)

    logging.info('Commission triggered via the NB Agent API with payload: %s ' % payload)

    commissioning_response = app.config["infra"].do_commission(payload)
    return jsonify(commissioning_response)


@app.route('/api/healthcheck', methods=['GET'])
def healthcheck():
    """ Static endpoint just for clients to check if API/Agent is up and running
    """

    return jsonify(True)


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
            message, return_code = AgentApi.modify(identifier, action=request.method, payload=payload)
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


if __name__ == "__main__":
    logging, args = init()

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

    # start telemetry
    logging.info("Starting telemetry...")
    telemetry = Telemetry(data_volume, nuvlabox_status_id)
    infra = Infrastructure(data_volume)

    nuvlabox_info_updated_date = ''
    refresh_interval = 5

    app.config["telemetry"] = telemetry
    app.config["infra"] = infra

    monitoring_thread = threading.Thread(target=app.run, kwargs={"host": "0.0.0.0", "port": "80"})
    monitoring_thread.daemon = True
    monitoring_thread.start()

    while True:
        nuvlabox_resource = activation.get_nuvlabox_info()
        if nuvlabox_info_updated_date != nuvlabox_resource['updated']:
            refresh_interval = nuvlabox_resource['refresh-interval']
            logging.warning('NuvlaBox resource updated. Refresh interval value: {}s'.format(refresh_interval))
            nuvlabox_info_updated_date = nuvlabox_resource['updated']
            activation.create_nb_document_file(nuvlabox_resource)

        # if there's a mention to the VPN server, then watch the VPN credential
        if nuvlabox_resource.get("vpn-server-id"):
            infra.watch_vpn_credential(nuvlabox_resource.get("vpn-server-id"))

        telemetry.update_status()

        infra.try_commission()
        e.wait(timeout=refresh_interval/2)
