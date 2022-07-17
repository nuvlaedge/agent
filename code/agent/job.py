#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Job

Relays pull-mode jobs to local job-engine-lite
"""

import logging
import json

from agent.common import NuvlaBoxCommon


class Job(NuvlaBoxCommon.NuvlaBoxCommon):
    """ The Job class, which includes all methods and
    properties necessary to handle pull mode jobs

    Attributes:
        data_volume: path to shared NuvlaBox data
        job_id: Nuvla UUID of the job
        job_engine_lite_image: Docker image for Job Engine lite
    """

    def __init__(self, data_volume, job_id, job_engine_lite_image):
        """ Constructs an Job object """

        super().__init__(shared_data_volume=data_volume)
        self.job_id = job_id
        self.job_id_clean = job_id.replace('/', '-')
        self.do_nothing = self.check_job_is_running()
        self.job_engine_lite_image = job_engine_lite_image

    def check_job_is_running(self):
        """ Checks if the job is already running """
        return self.container_runtime.is_nuvla_job_running(self.job_id, self.job_id_clean)

    def launch(self):
        """ Starts a Job Engine Lite container with this job

        :return:
        """
        try:
            with open(self.activation_flag) as a:
                user_info = json.loads(a.read())
        except FileNotFoundError:
            logging.error(f'Cannot find NuvlaBox API key for job {self.job_id}')
            return

        self.container_runtime.launch_job(
            self.job_id, self.job_id_clean, self.nuvla_endpoint,
            self.nuvla_endpoint_insecure,
            user_info["api-key"],
            user_info["secret-key"],
            self.job_engine_lite_image)
