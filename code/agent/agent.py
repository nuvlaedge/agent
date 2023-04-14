"""
This class gathers the main properties of the agent component of the NuvlaEdge engine.
Also controls the execution flow and provides utilities to the children dependencies
"""
import logging
import os
import threading
from copy import copy
from threading import Event, Thread
from typing import Union, NoReturn, List, Dict

from nuvla.api.models import CimiResource

from agent.activate import Activate
from agent.common import util
from agent.common.NuvlaEdgeCommon import NuvlaEdgeCommon
from agent.infrastructure import Infrastructure
from agent.job import Job
from agent.telemetry import Telemetry


class Agent:
    """
    Parent agent class in charge of gathering all the subcomponents and synchronize them
    """
    # Default shared volume location
    _DATA_VOLUME: str = "/srv/nuvlaedge/shared"

    # Event timeout controller
    agent_event: Event = Event()

    # pylint: disable=too-many-instance-attributes
    def __init__(self, agent_flag: bool):
        # Class logger
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.logger.debug('Instantiating Agent class')

        # Main NuvlaEdge data
        self.nuvlaedge_status_id: str = ''
        self.past_status_time: str = ''
        self.nuvlaedge_updated_date: str = ''
        self.agent_flag: bool = agent_flag

        self.excluded_monitors = os.environ.get('EXCLUDED_MONITORS', '')

        self._activate = None
        self._infrastructure = None
        self._nuvlaedge_common = None
        self._telemetry = None

        self.infrastructure_thread = None
        self.telemetry_thread = None

    @property
    def nuvlaedge_common(self) -> NuvlaEdgeCommon:
        """ Class containing mainly hardcoded paths, ports and addresses related tu nuvla """
        if not self._nuvlaedge_common:
            self.logger.info('Instantiating NuvlaEdgeCommon class')
            self._nuvlaedge_common = NuvlaEdgeCommon()
        return self._nuvlaedge_common

    @property
    def activate(self) -> Activate:
        """ Class responsible for activating and controlling previous nuvla installations """
        if not self._activate:
            self.logger.info('Instantiating Activate class')
            self._activate = Activate(self._DATA_VOLUME)
        return self._activate

    @property
    def infrastructure(self) -> Infrastructure:
        """ Intermediary class which provides and interface to communicate with nuvla """
        if not self._infrastructure:
            self.logger.info('Instantiating Infrastructure class')
            self._infrastructure = Infrastructure(self._DATA_VOLUME,
                                                  telemetry=self.telemetry)
            self.initialize_infrastructure()
        return self._infrastructure

    @property
    def telemetry(self) -> Telemetry:
        """ Telemetry updater class """
        if not self._telemetry:
            self.logger.info('Instantiating Telemetry class')
            self._telemetry = Telemetry(self._DATA_VOLUME,
                                        self.nuvlaedge_status_id,
                                        self.excluded_monitors)
        return self._telemetry

    def activate_nuvlaedge(self) -> NoReturn:
        """
        Creates an "activate" object class and uses it to check the previous status
        of the NuvlaEdge. If it was activated before, it gathers the previous status.
        If not, it activates the device and again gathers the status
        """

        self.logger.info(f'Nuvla endpoint: {self.activate.nuvla_endpoint}')
        self.logger.info(
            f'Nuvla connection insecure: {str(self.activate.nuvla_endpoint_insecure)}')

        while True:
            can_activate, user_info = self.activate.activation_is_possible()
            if can_activate or user_info:
                break
            else:
                self.logger.info(f'Activation not yet possible {can_activate}-{user_info}')

            self.agent_event.wait(timeout=3)

        if not user_info:
            self.logger.info('NuvlaEdge not yet activated, proceeding')
            self.activate.activate()

        # Gather resources post-activation
        nuvlaedge_resource, old_nuvlaedge_resource = \
            self.activate.update_nuvlaedge_resource()
        self.nuvlaedge_status_id = nuvlaedge_resource["nuvlabox-status"]
        self.logger.info(f'NuvlaEdge status id {self.nuvlaedge_status_id}')

    def initialize_infrastructure(self) -> NoReturn:
        """
        Initializes the infrastructure class

        Returns: None
        """
        if not self.infrastructure.installation_home:
            self.logger.warning('Host user home directory not defined.'
                                'This might impact future SSH management actions')
        else:
            util.atomic_write(self.infrastructure.host_user_home_file,
                              self.infrastructure.installation_home,
                              encoding='UTF-8')
            self.infrastructure.set_immutable_ssh_key()

    def initialize_telemetry(self) -> NoReturn:
        pass

    def initialize_agent(self) -> bool:
        """
        This method sequentially initializes al the NuvlaEdge main components.

        Returns: True if the initialization is successful.  False, otherwise

        """
        # 1. Proceed with the initialization of the NuvlaEdge
        self.activate_nuvlaedge()

        # 2. Initialization of the telemetry class
        # self.initialize_telemetry()

        # 3. Initialize Infrastructure class
        # self.initialize_infrastructure()

        return True

    def send_heartbeat(self) -> Dict:
        """
        Updates the NuvlaEdge Status according to the local status file

        Returns: a dict with the response from Nuvla
        """
        self.logger.debug(f'send_heartbeat({self.nuvlaedge_common}, '
                          f'{self.telemetry}, {self.nuvlaedge_status_id},'
                          f' {self.past_status_time})')

        # Calculate differences NE-Nuvla status
        status, _del_attr = self.telemetry.diff(self.telemetry.status_on_nuvla,
                                                self.telemetry.status)
        status_current_time = self.telemetry.status.get('current-time', '')
        del_attr: List = []

        self.logger.debug(f'send_heartbeat: status_current_time = {status_current_time} '
                          f'_delete_attributes = {_del_attr}  status = {status}')

        if not status_current_time:
            status = {'status-notes': ['NuvlaEdge Telemetry is starting']}
            self.telemetry.status.update(status)

        else:
            if status_current_time <= self.past_status_time:
                status = {
                    'status-notes': status.get('status-notes', []) + [
                        'NuvlaEdge telemetry is falling behind'],
                    'status': 'DEGRADED'
                }
                self.telemetry.status.update(status)
            else:
                del_attr = _del_attr

        if del_attr:
            self.logger.info(f'Deleting the following attributes from NuvlaEdge Status: '
                             f'{", ".join(del_attr)}')

        try:
            resource: CimiResource = self.nuvlaedge_common.api().edit(
                self.nuvlaedge_status_id,
                data=status,
                select=del_attr)

            self.telemetry.status_on_nuvla.update(status)

        except:
            self.logger.error("Unable to update NuvlaEdge status in Nuvla")
            raise

        self.past_status_time = copy(status_current_time)

        return resource.data

    def run_pull_jobs(self, job_list):
        """
        Handles the pull jobs one by one, sequentially
        Args:
            job_list: list of job IDs
        """
        for job_id in job_list:
            job: Job = Job(self._DATA_VOLUME,
                           job_id,
                           self.infrastructure.container_runtime.job_engine_lite_image)

            if not job.do_nothing:

                try:
                    job.launch()
                except Exception as ex:
                    # catch all
                    self.logger.error(f'Cannot process job {job_id}. Reason: {str(ex)}')

    def handle_pull_jobs(self, response: Dict):
        """
        Reads the response from the heartbeat and executes the jobs received from Nuvla
        Args:
            response: Heartbeat received response

        Returns:

        """
        pull_jobs: List = response.get('jobs', [])
        if not isinstance(pull_jobs, list):
            self.logger.warning(f'Jobs received on format {response.get("jobs")} not '
                                f'compatible')
            return

        if pull_jobs and self.infrastructure.container_runtime.job_engine_lite_image:
            self.logger.info(f'Processing jobs {pull_jobs} in pull mode')

            threading.Thread(
                target=self.run_pull_jobs,
                args=(pull_jobs,),
                daemon=True).start()

        else:
            self.logger.debug('No pull jobs to run')

    def run_single_cycle(self):
        """
        Controls the main functionalities of the agent:
            1. Sending heartbeat
            2. Running pull jobs
        """

        def is_thread_creation_needed(name, thread):
            if not thread:
                self.logger.info(f'Creating {name} thread')
            elif not thread.is_alive():
                self.logger.warning(f'Recreating {name} thread because it is not alive')
            else:
                self.logger.debug(f'Thread {name} is alive')
                return False
            return True

        def create_start_thread(**kwargs):
            th = threading.Thread(daemon=True, **kwargs)
            th.start()
            return th

        if is_thread_creation_needed('Telemetry', self.telemetry_thread):
            self.telemetry_thread = create_start_thread(name='Telemetry',
                                                        target=self.telemetry.update_status)

        response: Dict = self.send_heartbeat()

        self.handle_pull_jobs(response)

        if is_thread_creation_needed('Infrastructure', self.infrastructure_thread):
            self.infrastructure_thread = create_start_thread(name='Infrastructure',
                                                             target=self.infrastructure.run)

