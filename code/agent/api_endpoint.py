"""
Controls the local endpoint API to allow other modules to modify, add or subscribe to the
agent
"""
import json
import logging
import socket

from flask import Flask, request, jsonify

from agent import agent_api

app: Flask = Flask(__name__)
endpoint_logger: logging.Logger = logging.getLogger(__name__)


@app.route('/api/status')
def set_status():
    """ API endpoint to let other components set the NuvlaBox status """

    value = request.args.get('value')
    log = str(request.args.get('log'))

    if not value:
        endpoint_logger.warning("Received status request with no value. Nothing to do")
    else:
        endpoint_logger.info(f"Setting NuvlaBox status to {value}")
        if log:
            print(app.config["telemetry"], dir(app.config["telemetry"]))

    endpoint_logger.warning('to be implemented')
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
    except socket.gaierror as ex:
        return jsonify(str(ex)), 404


@app.route('/api/commission', methods=['POST'])
def trigger_commission():
    """ API endpoint to let other components trigger a commissioning

    The request.data is the payload
    """

    payload = json.loads(request.data)

    endpoint_logger.info('Commission triggered via the NB Agent API')

    commissioning_response = app.config["infra"].do_commission(payload)
    return jsonify(commissioning_response)


@app.route('/api/set-vulnerabilities', methods=['POST'])
def set_vulnerabilities():
    """ API endpoint to let other components send and save the scanned vulnerabilities

    The request.data is the payload
    """

    payload = json.loads(request.data)

    endpoint_logger.info(f'Saving vulnerabilities received via the API: {payload}')

    agent_api.save_vulnerabilities(payload)

    return jsonify(True), 201


@app.route('/api/set-vpn-ip', methods=['POST'])
def set_vpn_ip():
    """ API endpoint to let other components define the NB VPN IP
    """

    payload = request.data

    endpoint_logger.info(f'Received request to set VPN IP to {payload}')

    agent_api.save_vpn_ip(payload)
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

    endpoint_logger.info(f'  ####   Received {request.method} request for peripheral'
                         f' management')

    payload = {}
    if request.data:
        try:
            payload = json.loads(request.data)
        except json.JSONDecodeError:
            return jsonify({"error": f"Payload {payload} malformed. It must be a JSON "
                                     "payload"}), 400

    if identifier:
        endpoint_logger.info(f'#### {request.method} peripheral {identifier}')
        if request.method in ["DELETE", "PUT"]:
            # DELETE accepts resource ID for simplicity and backward compatibility
            resource_id = request.args.get('id')

            message, return_code = agent_api.modify(identifier,
                                                    peripheral_nuvla_id=resource_id,
                                                    action=request.method,
                                                    payload=payload)

        elif request.method == "GET":
            message, return_code = agent_api.get(identifier)

        else:
            endpoint_logger.info(f'####  Method {request.method} not implemented yet!!')
            message = "Not implemented"
            return_code = 501

    else:
        # POST or FIND peripheral
        if request.method == "POST":
            endpoint_logger.info(f'####  Creating new peripheral with payload {payload}')
            message, return_code = agent_api.post(payload)
        else:
            # GET
            parameter = request.args.get('parameter')
            value = request.args.get('value')
            identifier_pattern = request.args.get('identifier_pattern')
            endpoint_logger.info(f'####  Find peripherals with {parameter}={value}')
            message, return_code = agent_api.find(parameter, value, identifier_pattern)

    return jsonify(message), return_code
