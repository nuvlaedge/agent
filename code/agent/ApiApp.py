#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import socket

import agent.AgentApi as AgentApi

from flask import Flask, request, jsonify, Response


app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route('/api/status')
def set_status():
    """ API endpoint to let other components set the NuvlaBox status """

    value = request.args.get('value')
    log = str(request.args.get('log'))

    if not value:
        logger.warning("Received status request with no value. Nothing to do")
    else:
        logger.info("Setting NuvlaBox status to {}".format(value))
        if log:
            print(app.config["telemetry"], dir(app.config["telemetry"]))

    logger.warning('to be implemented')
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

    logger.info('Commission triggered via the NB Agent API with payload: %s ' % payload)

    commissioning_response = app.config["infra"].do_commission(payload)
    return jsonify(commissioning_response)


@app.route('/api/set-vulnerabilities', methods=['POST'])
def set_vulnerabilities():
    """ API endpoint to let other components send and save the scanned vulnerabilities

    The request.data is the payload
    """

    payload = json.loads(request.data)

    logger.info('Saving vulnerabilities received via the API: %s ' % payload)

    AgentApi.save_vulnerabilities(payload)

    return jsonify(True), 201


@app.route('/api/set-vpn-ip', methods=['POST'])
def set_vpn_ip():
    """ API endpoint to let other components define the NB VPN IP
    """

    payload = request.data

    logger.info('Received request to set VPN IP to %s ' % payload)

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

    logger.info('  ####   Received %s request for peripheral management' % request.method)

    payload = {}
    if request.data:
        try:
            payload = json.loads(request.data)
        except:
            return jsonify({"error": "Payload {} malformed. It must be a JSON payload".format(payload)}), 400

    if identifier:
        logger.info('  ####   %s peripheral %s' % (request.method, identifier))
        if request.method in ["DELETE", "PUT"]:
            # DELETE accepts resource ID for simplicity and backward compatibility
            resource_id = request.args.get('id')
            message, return_code = AgentApi.modify(identifier, peripheral_nuvla_id=resource_id,
                                                   action=request.method, payload=payload)
        elif request.method == "GET":
            message, return_code = AgentApi.get(identifier)
        else:
            logger.info('  ####   Method %s not implemented yet!!' % request.method)
            message = "Not implemented"
            return_code = 501
    else:
        # POST or FIND peripheral
        if request.method == "POST":
            logger.info('  ####   Creating new peripheral with payload %s' % payload)
            message, return_code = AgentApi.post(payload)
        else:
            # GET
            parameter = request.args.get('parameter')
            value = request.args.get('value')
            identifier_pattern = request.args.get('identifier_pattern')
            logger.info('  ####   Find peripherals with {}={}'.format(parameter, value))
            message, return_code = AgentApi.find(parameter, value, identifier_pattern)

    return jsonify(message), return_code
