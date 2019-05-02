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
from .agent.common import nuvlabox as nb
from .agent.Activate import Activate
from .agent.Telemetry import Telemetry
from threading import Event

__copyright__ = "Copyright (C) 2019 SixSq"
__email__ = "support@sixsq.com"

DATA_VOLUME = "/srv/nuvlabox/shared"
LOG_FILENAME = "agent.log"
NETWORK_TIMEOUT = 10

def init():
    """ Initialize the application, including argparsing """

    description = 'NuvlaBox Agent'
    params = nb.arguments(description, DATA_VOLUME, LOG_FILENAME).parse_args()

    logger = nb.logger(nb.get_log_level(params), params.log_file)

    return logger, params


if __name__ == "__main__":
    logging, args = init()

    socket.setdefaulttimeout(NETWORK_TIMEOUT)

    # Try to activate the NuvlaBox
    activation = Activate(args.data_volume)
    user_info = activation.activation_is_possible()
    if not user_info:
        # this NuvlaBox hasn't been activated yet
        user_info = activation.activate()
        activation.update_nuvlabox_record()

    # start telemetry
    logging.info("Starting telemetry...")
    telemetry = Telemetry(args.data_volume, api=activation.api)

    e = Event()
    nuvlabox_info_updated_date = ''
    refresh_interval = 5

    while True:
        nuvlabox_record = nb.get_nuvlabox_info(telemetry.api)
        if nuvlabox_info_updated_date != nuvlabox_record['updated']:
            refresh_interval = nuvlabox_record['refreshInterval']
            logging.warn('NuvlaBox record updated. Refresh interval value: {}s'.format(refresh_interval))
            nuvlabox_info_updated_date = nuvlabox_record['updated']
            nb.create_context_file(nuvlabox_record, telemetry.data_volume)

        next_check = datetime.datetime.utcnow() + datetime.timedelta(seconds=refresh_interval)
        telemetry.udpate_state(next_check)

        e.wait(timeout=refresh_interval)

