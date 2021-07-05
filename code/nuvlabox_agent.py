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

import logging
import signal
import socket
import sys
import threading
import time
import faulthandler, traceback

from agent.common import NuvlaBoxCommon
from agent.Activate import Activate
from agent.ApiApp  import app
from agent.Telemetry import Telemetry
from agent.Infrastructure import Infrastructure
from agent.Job import Job

__copyright__ = "Copyright (C) 2019 SixSq"
__email__ = "support@sixsq.com"

data_volume = "/srv/nuvlabox/shared"
network_timeout = 10

logger = logging.getLogger(__name__)
nuvlabox_info_updated_date = ''
refresh_interval = 5
stop_event = threading.Event()


def init():
    """
    Initialize the application, including argparsing
    """
    socket.setdefaulttimeout(network_timeout)

    signal.signal(signal.SIGTERM, signal_term)
    signal.signal(signal.SIGUSR1, signal_usr1)

    params = NuvlaBoxCommon.arguments().parse_args()
    root_logger = NuvlaBoxCommon.logger(NuvlaBoxCommon.get_log_level(params))

    return root_logger, params


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
            logger.error(f'Cannot process job {job_id}. Reason: {str(ex)}')


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
    global nuvlabox_info_updated_date

    if nuvlabox_resource.get('state', '').startswith('DECOMMISSION'):
        logger.warning(f'This NuvlaBox is {nuvlabox_resource["state"]} in Nuvla. Exiting...')
        stop_event.set()

    if nb_updated_date != nuvlabox_resource['updated'] and not stop_event.is_set():
        refresh_interval = nuvlabox_resource['refresh-interval']
        logger.warning('NuvlaBox resource updated. Refresh interval value: {}s'.format(refresh_interval))
        nuvlabox_info_updated_date = nuvlabox_resource['updated']
        activation_class_object.create_nb_document_file(nuvlabox_resource)

    # if there's a mention to the VPN server, then watch the VPN credential
    if nuvlabox_resource.get("vpn-server-id"):
        infra_class_object.watch_vpn_credential(nuvlabox_resource.get("vpn-server-id"))


def log_threads_stackstraces():
    print_args = dict(file=sys.stderr, flush=True)
    print("\nfaulthandler.dump_traceback()", **print_args)
    faulthandler.dump_traceback()
    print("\nthreading.enumerate()", **print_args)
    for th in threading.enumerate():
        print(th, **print_args)
        traceback.print_stack(sys._current_frames()[th.ident])
    print(**print_args)


def signal_usr1(signum, frame):
    log_threads_stackstraces()


def signal_term(signum, frame):
    print(f'Signal {signum} received', file=sys.stderr, flush=True)
    stop_event.set()


def nb_check(nb_checker, activation, infra):
    if not nb_checker or not nb_checker.is_alive():
        nb_checker = threading.Thread(name='agent_preflight_check', target=preflight_check,
                                      args=(activation, infra, nuvlabox_info_updated_date,),
                                      daemon=True)
        nb_checker.start()
    return nb_checker


def start_api_in_a_thread(telemetry, infra):
    app.config["telemetry"] = telemetry
    app.config["infra"] = infra

    api_thread = threading.Thread(name='agent_api', target=app.run,
                                  kwargs={"host": "0.0.0.0", "port": "80"})
    api_thread.daemon = True
    api_thread.start()


def wait_can_activate_or_user_info(activation):
    with NuvlaBoxCommon.timeout(60, True):
        while not stop_event.is_set():
            can_activate, user_info = activation.activation_is_possible()
            if can_activate or user_info:
               break
            stop_event.wait(timeout=3)
    return can_activate, user_info


def handle_jobs_in_a_thread(jobs, infra):
    if jobs and isinstance(jobs, list) and infra.container_runtime.job_engine_lite_image:
        logger.info(f'Processing the following jobs in pull-mode: {jobs}')
        threading.Thread(name='agent_jobs', target=manage_pull_jobs,
                         args=(jobs, infra.container_runtime.job_engine_lite_image,),
                         daemon=True).start()


def handle_commission_in_a_thread(infra):
    if not infra.is_alive():
        infra = Infrastructure(data_volume, refresh_period=refresh_interval)
        infra.start()


def handle_activation(activation):
    can_activate, user_info = wait_can_activate_or_user_info(activation)
    if can_activate and not user_info:  # this NuvlaBox hasn't been activated yet
        logger.info("Starting activation...")
        activation.activate()
    nuvlabox_status_id = activation.update_nuvlabox_resource()
    return nuvlabox_status_id


def get_running_threads_except_main_thread():
    return [t for t in threading.enumerate() if t != threading.main_thread()]


def wait_all_threads_terminate():
    main_thread = threading.main_thread()
    current_thread = threading.current_thread()

    if current_thread != main_thread:
        logger.error(f'This function can only be run from the main thread '
                     f'not from "{current_thread}". Ignoring.')
        return

    logger.info('Give a chance to threads to terminate gracefully')
    start_time = time.time()
    while (time.time() - start_time) < 30:
        for thread in get_running_threads_except_main_thread():
            logger.debug(f'Waiting for thread "{thread.name}" to terminate')
            try:
                thread.join(2)
            except RuntimeError:
                pass
            if thread.is_alive():
                logger.debug(f'Thread "{thread.name}" still runing')
            else:
                logger.debug(f'Thread "{thread.name}" terminated')
        if len(threading.enumerate()) == 1:
            break
    running_threads = ','.join([t.name for t in get_running_threads_except_main_thread()])
    logger.warning(f'The following threads are still running: {running_threads}')


def main():
    global nuvlabox_info_updated_date
    global refresh_interval

    try:
        activation = Activate(data_volume)

        nuvlabox_status_id = handle_activation(activation)

        telemetry = Telemetry(data_volume, nuvlabox_status_id)
        infra = Infrastructure(data_volume)

        infra.set_immutable_ssh_key()

        start_api_in_a_thread(telemetry, infra)

        logger.info("Starting telemetry...")
        nb_checker = None
        while not stop_event.is_set():
            nb_checker = nb_check(nb_checker, activation, infra)

            start_cycle = time.time()

            response = telemetry.update_status()
            jobs = response.get('jobs')

            handle_jobs_in_a_thread(jobs, infra)

            handle_commission_in_a_thread(infra)

            cycle_duration = time.time() - start_cycle
            next_cycle_in = refresh_interval - cycle_duration

            stop_event.wait(timeout=next_cycle_in)
    finally:
        wait_all_threads_terminate()


if __name__ == "__main__":
    init()
    main()
