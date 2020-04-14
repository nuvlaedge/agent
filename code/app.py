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

    final_log_file = params.log_file if params.log_file else default_log_filename

    logger = NuvlaBoxCommon.logger(NuvlaBoxCommon.get_log_level(params), final_log_file)

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
    return "Hello World!"


@app.route('/api/commission', methods=['POST'])
def trigger_commission():
    """ API endpoint to let other components trigger a commissioning

    The request.data is the payload
    """

    payload = json.loads(request.data)

    logging.info('Commission triggered via the NB Agent API with payload: %s ' % payload)

    commissioning_response = app.config["infra"].do_commission(payload)
    return jsonify(commissioning_response)


@app.route('/api/peripheral/', defaults={'identifier': None}, methods=['POST'])
@app.route('/api/peripheral/<identifier>', methods=['GET', 'PUT', 'DELETE'])
def manage_peripheral(identifier):
    """ API endpoint to let other components manage NuvlaBox peripherals

    :param identifier: local id of the peripheral to be managed
    """

    logging.info('Received %s request for peripheral management' % request.method)

    payload = None
    if request.data:
        payload = json.loads(request.data)

    if identifier:
        if request.method == "DELETE":
            message, return_code = AgentApi.delete(identifier)
        else:
            message = "Not implemented"
            return_code = 501
    else:
        # POST peripheral
        message, return_code = AgentApi.post(payload)

    return Response(message, status=return_code)


if __name__ == "__main__":
    logging, args = init()

    socket.setdefaulttimeout(network_timeout)

    e = Event()
    # Try to activate the NuvlaBox
    activation = Activate(data_volume)
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

    monitoring_thread = threading.Thread(target=app.run, kwargs={"host": "0.0.0.0"})
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
