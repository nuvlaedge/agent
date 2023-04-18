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


@app.route('/api/commission', methods=['POST'])
def trigger_commission():
    """ API endpoint to let other components trigger a commissioning

    The request.data is the payload
    """

    payload = json.loads(request.data)
    endpoint_logger.info('Commission triggered via the NB Agent API')

    commissioning_response = app.config["infrastructure"].do_commission(payload)

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
