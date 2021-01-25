#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Job

Relays pull-mode jobs to local job-engine-lite
"""

import logging
import docker
import json

from agent.common import NuvlaBoxCommon


class Job(NuvlaBoxCommon.NuvlaBoxCommon):
    """ The Job class, which includes all methods and
    properties necessary to handle pull mode jobs

    Attributes:
        data_volume: path to shared NuvlaBox data
        job_id: Nuvla UUID of the job
    """

    def __init__(self, data_volume, job_id):
        """ Constructs an Job object """

        super().__init__(shared_data_volume=data_volume)
        self.job_id = job_id
        self.job_id_clean = job_id.replace('/', '-')
        self.do_nothing = self.check_job_is_running()

    def check_job_is_running(self):
        """ Checks if the job is already running """

        try:
            job_container = self.docker_client.containers.get(self.job_id_clean)
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logging.error(f'Cannot handle job {self.job_id}. Reason: {str(e)}')
            # assume it is running so we don't mess anything
            return True

        try:
            if job_container.status.lower() in ['running', 'restarting']:
                logging.info(f'Job {self.job_id} is already running in container {job_container.name}')
                return True
            else:
                # then it is stopped or dead. force kill it and re-initiate
                job_container.kill()
        except AttributeError:
            # assume it is running so we don't mess anything
            return True
        except docker.errors.NotFound:
            # then it stopped by itself...maybe it ran already and just finished
            # let's not do anything just in case this is a late coming job. In the next telemetry cycle, if job is there
            # again, then we run it because this container is already gone
            return True

        return False

    def launch(self):
        """ Starts a Job Engine Lite container with this job

        :return:
        """

        try:
            with open(self.activation_flag) as a:
                user_info = json.loads(a.read())
        except FileNotFoundError:
            return

        cmd = f'-- /app/job_executor.py --api-url https://{self.nuvla_endpoint} ' \
            f'--api-insecure {self.nuvla_endpoint_insecure} ' \
            f'--api-key {user_info["api-key"]} ' \
            f'--api-secret {user_info["secret-key"]}'

        self.docker_client.containers.run(self.job_engine_lite_image,
                                          command=cmd,
                                          detach=True,
                                          name=self.job_id_clean,
                                          hostname=self.job_id_clean,
                                          remove=True,
                                          volumes={
                                              '/var/run/docker.sock': {
                                                  'bind': '/var/run/docker.sock',
                                                  'mode': 'ro'
                                              }
                                          }
                                          )
