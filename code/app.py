#!/usr/local/bin/python3.7
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
import datetime
import threading
from flask import Flask, request
from agent.common import nuvlabox as nb
from agent.Activate import Activate
from agent.Telemetry import Telemetry
from agent.Infrastructure import Infrastructure
from threading import Event

__copyright__ = "Copyright (C) 2019 SixSq"
__email__ = "support@sixsq.com"

app = Flask(__name__)
data_volume = "/srv/nuvlabox/shared"
log_filename = "agent.log"
network_timeout = 10


def init():
    """ Initialize the application, including argparsing """

    description = 'NuvlaBox Agent'
    params = nb.arguments(description, data_volume, log_filename).parse_args()

    logger = nb.logger(nb.get_log_level(params), params.log_file)

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


if __name__ == "__main__":
    logging, args = init()

    socket.setdefaulttimeout(network_timeout)

    e = Event()

    # Try to activate the NuvlaBox
    activation = Activate(args.data_volume)
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
    telemetry = Telemetry(args.data_volume, nuvlabox_status_id, api=activation.api)
    infra = Infrastructure(args.data_volume, api=activation.api)

    nuvlabox_info_updated_date = ''
    refresh_interval = 5

    app.config["telemetry"] = telemetry

    monitoring_thread = threading.Thread(target=app.run)
    monitoring_thread.daemon = True
    monitoring_thread.start()

    while True:
        logging.info('beginning of agent loop')
        nuvlabox_resource = nb.get_nuvlabox_info(telemetry.api)
        logging.info('got nuvlabox resource')
        if nuvlabox_info_updated_date != nuvlabox_resource['updated']:
            logging.info('nuvlabox resource update')
            refresh_interval = nuvlabox_resource['refresh-interval']
            logging.warning('NuvlaBox resource updated. Refresh interval value: {}s'.format(refresh_interval))
            nuvlabox_info_updated_date = nuvlabox_resource['updated']
            nb.create_context_file(nuvlabox_resource, telemetry.data_volume)
            logging.info('end nuvlabox resource update')

        current_time = datetime.datetime.utcnow()
        logging.info('before status')
        telemetry.update_status(current_time)
        logging.info('after status')

        logging.info('before commission')
        infra.try_commission()
        logging.info('after commission')
        e.wait(timeout=refresh_interval/2)
