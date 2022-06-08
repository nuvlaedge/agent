#!/usr/local/bin/python3.7
"""
Main entrypoint script for the agent component in the NuvlaEdge engine
Controls all the functionalities of the Agent
"""

from argparse import ArgumentParser
import os
import sys
import logging
from logging import config as log_config_mod
import time
from typing import Union, Dict
from threading import Event, Thread

import requests

import agent.api_endpoint as endpoint
from agent import Agent, Activate, Infrastructure
from agent.common import NuvlaBoxCommon

# Logging globals
log_format: str = '[%(asctime)s - %(name)s/%(funcName)s - %(levelname)s]: %(message)s'
default_log_filename: str = 'agent.log'

# Nuvlaedge globals
data_volume: str = '/srv/nuvlabox/shared'
network_timeout: int = 10
refresh_interval: int = 30


def parse_arguments() -> ArgumentParser:
    """
    Argument parser configuration for the agent
    Returns: ArgumentParser. A configured argument parser object class

    """
    parser: ArgumentParser = ArgumentParser(description="NuvlaBox Agent")
    parser.add_argument('--debug', dest='debug', default=False, action='store_true',
                        help='use for increasing the verbosity level')

    return parser


def configure_root_logger(logger: logging.Logger, debug: bool):
    """
    Configures the root logger based on the environmental variables

    Args:
        logger: root logger to be configured
        debug: debug verbosity flag
    """
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        env_level: str = os.environ.get('NUVLABOX_LOG_LEVEL', '')
        if env_level:
            logger.setLevel(logging.getLevelName(env_level))
        else:
            logger.setLevel(logging.INFO)

    # Setting flask server verbosity to warnings
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)


def configure_endpoint_api(agent: Agent) -> Thread:
    """
    Configures the Flask API app  endpoint with the agent components.

    Args:
        agent: Main agent class. This class has to be initialized before getting here
    """
    endpoint.app.config['telemetry'] = agent.telemetry
    endpoint.app.config['infrastructure'] = agent.infrastructure
    it_thread: Thread = Thread(target=endpoint.app.run,
                               kwargs={"host": "0.0.0.0",
                                       "port": "80",
                                       "debug": True,
                                       'use_reloader': False},
                               daemon=True)
    it_thread.start()

    with NuvlaBoxCommon.timeout(10):
        root_logger.info('Waiting for API to be ready...')
        wait_for_api_ready()

    return it_thread


def wait_for_api_ready():
    """
    Waits in a loop for the API to be ready
    :return:
    """
    while True:
        try:
            req = requests.get('http://localhost/api/healthcheck')
            req.raise_for_status()
            if req.status_code == 200:
                break
        except (requests.HTTPError, requests.exceptions.RequestException):
            time.sleep(1)

    root_logger.info('NuvlaBox Agent has been initialized.')


def preflight_check(activator: Activate, exit_flag: bool, nb_updated_date: str,
                    infra: Infrastructure):
    """
    Checks if the NuvlaBox resource has been updated in Nuvla

    Args:
        activator: instance of Activate
        infra:
        nb_updated_date:
        exit_flag:
    """
    global refresh_interval

    nuvlabox_resource: Dict = activator.get_nuvlabox_info()
    if nuvlabox_resource.get('state', '').startswith('DECOMMISSION'):
        exit_flag = False

    if nb_updated_date != nuvlabox_resource['updated'] and exit_flag:
        refresh_interval = nuvlabox_resource['refresh-interval']
        root_logger.info(f'NuvlaBox resource updated. Refresh interval value: '
                         f'{refresh_interval}')

        nb_updated_date = nuvlabox_resource['updated']
        old_nuvlabox_resource = activator.create_nb_document_file(nuvlabox_resource)
        activator.vpn_commission_if_needed(nuvlabox_resource, old_nuvlabox_resource)

    # if there's a mention to the VPN server, then watch the VPN credential
    if nuvlabox_resource.get("vpn-server-id"):
        infra.watch_vpn_credential(nuvlabox_resource.get("vpn-server-id"))


def main():
    """
    Initialize the main agent class. This class will also initialize submodules:
      - Activator
      - Telemetry
      - Infrastructure

    Returns: None

    """

    main_event: Event = Event()
    agent_exit_flag: bool = True

    main_agent: Agent = Agent(agent_exit_flag)
    main_agent.initialize_agent()

    watchdog_thread: Union[Thread, None] = None
    nuvlabox_info_updated_date: str = ''

    # Setup Endpoint API
    api_thread: Thread = configure_endpoint_api(main_agent)

    while agent_exit_flag:
        # Time Start
        start_cycle: float = time.time()
        # ----------------------- Main Agent functionality ------------------------------

        if not api_thread or not api_thread.is_alive():
            api_thread = configure_endpoint_api(main_agent)

        if not watchdog_thread or not watchdog_thread.is_alive():
            watchdog_thread = Thread(target=preflight_check,
                                     args=(main_agent.activate,
                                           agent_exit_flag,
                                           nuvlabox_info_updated_date,
                                           main_agent.infrastructure
                                           ,),
                                     daemon=True)
            watchdog_thread.start()

        main_agent.run_single_cycle()

        # -------------------------------------------------------------------------------

        # Account cycle time
        cycle_duration = time.time() - start_cycle
        next_cycle_in = refresh_interval - cycle_duration - 1
        root_logger.debug(f'End of cycle. Cycle duration: {cycle_duration} sec. Next '
                          f'cycle in {next_cycle_in} sec.')

        main_event.wait(timeout=next_cycle_in)


if __name__ == '__main__':
    # Global logging configuration
    log_config_mod.fileConfig('agent/config/agent_logger_config.conf')

    agent_parser: ArgumentParser = parse_arguments()

    # Logger for the root script
    root_logger: logging.Logger = logging.getLogger()
    configure_root_logger(root_logger, agent_parser.parse_args().debug)
    root_logger.info('Configuring Agent class and main script')

    main()
