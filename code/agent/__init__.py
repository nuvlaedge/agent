"""
This class gathers the main properties of the agent component of the NuvlaEdge engine.
Also controls the execution flow and provides utilities to the children dependencies
"""
import logging
import os
import threading
from threading import Event, Thread
from typing import Union, NoReturn, List, Dict

from nuvla.api.models import CimiResource

from agent.infrastructure import Infrastructure
from agent.job import Job
from agent.telemetry import Telemetry
from agent.activate import Activate
from agent.common.NuvlaBoxCommon import NuvlaBoxCommon


class Agent:
    """
    Parent agent class in change of gathering all the subcomponents and synchronize them
    """
    # Default shared volume location
    _DATA_VOLUME: str = "/srv/nuvlabox/shared"
    # Class logger
    logger: logging.Logger = logging.getLogger(__name__)

    # Main NuvlaEdge data
    nuvlaedge_status_id: str = ''
    past_status_time: str = ''
    nuvlaedge_updated_date: str = ''

    # Event timeout controller
    agent_event: Event = Event()

    # Telemetry updater class
    telemetry: Union[Telemetry, None] = None
    telemetry_thread: Union[Thread, None] = None

    # Class responsible for activating an controlling previous nuvla installations
    activate: Union[Activate, None] = None

    # pylint: disable=too-many-instance-attributes
    def __init__(self, agent_flag: bool):

        self.agent_flag: bool = agent_flag

        # Class containing  mainly hardcoded paths, ports and addresses related tu nuvla
        self.nuvlaedge_common: NuvlaBoxCommon = NuvlaBoxCommon()

        # Intermediary class which provides and interface to communicate with nuvla
        self.infrastructure: Infrastructure = Infrastructure(self._DATA_VOLUME)

    def activate_nuvlaedge(self) -> NoReturn:
        """
        Creates and activate object class and uses it to check the previous status
        of the NuvlaEdge. If it was activated before, it gathers the previous status.
        If not, it activates the device and again gathers the status

        """

        self.activate = Activate(self._DATA_VOLUME)
        self.logger.info(f'Nuvla endpoint: {self.activate.nuvla_endpoint}')
        self.logger.info(
            f'Nuvla connection insecure: {str(self.activate.nuvla_endpoint_insecure)}')

        while True:
            can_activate, user_info = self.activate.activation_is_possible()
            if can_activate or user_info:
                break

            self.agent_event.wait(timeout=3)

        if not user_info:
            self.logger.info('NuvlaEdge not yet activated, proceeding')
            self.activate.activate()

        # Gather resources post-activation
        nuvlaedge_resource, old_nuvlaedge_resource = \
            self.activate.update_nuvlabox_resource()
        self.nuvlaedge_status_id = nuvlaedge_resource["nuvlabox-status"]
        self.activate.vpn_commission_if_needed(nuvlaedge_resource, old_nuvlaedge_resource)
        self.logger.debug(f'NuvlaEdge status id {self.nuvlaedge_status_id}')

    def initialize_infrastructure(self) -> NoReturn:
        """
        Initializes the infrastructure class of the agent and check minimum requirements
        Returns: None

        """

        self.infrastructure = Infrastructure(self._DATA_VOLUME, telemetry=self.telemetry)
        if not self.infrastructure.installation_home:
            self.logger.warning('Host user home directory not defined.'
                                'This might impact future SSH management actions')
        else:
            with open(self.infrastructure.host_user_home_file, 'w', encoding='UTF-8') \
                    as user_home:
                user_home.write(self.infrastructure.installation_home)

    def initialize_telemetry(self) -> NoReturn:
        """
        Gathers the required environmental data and creates the nuvlabox telemetry class
        Returns:

        """
        self.logger.debug('Initializing Telemetry')
        non_active_monitors: str = os.environ.get('EXCLUDED_MONITORS', '')
        self.telemetry = Telemetry(self._DATA_VOLUME, self.nuvlaedge_status_id,
                                   non_active_monitors)

    def initialize_agent(self) -> bool:
        """
        This method sequentially initializes al the NuvlaEdge main components.

        Returns: True if the initialization is successful.  False, otherwise

        """
        # 1. Proceed with the initialization of the NuvlaEdge
        self.activate_nuvlaedge()

        # 2. Initialization of the telemetry class
        self.initialize_telemetry()

        # 3. Initialize Infrastructure class
        self.initialize_infrastructure()

        return True

    def send_heartbeat(self) -> Dict:
        """
        Updates the NuvlaBox Status according to the local status file

        Returns: a dict with the response from Nuvla
        """
        self.logger.debug(f'send_heartbeat({self.nuvlaedge_common}, '
                          f'{self.telemetry}, {self.nuvlaedge_status_id},'
                          f' {self.past_status_time})')

        # Calculate differences NE-Nuvla status
        status, _del_attr = self.telemetry.diff(self.telemetry.status_on_nuvla,
                                                self.telemetry.status)
        # self.logger.error(f'\nStatus on nuvla {self.telemetry.status_on_nuvla}')
        # self.logger.error(f'\nStatus on edge '
        #                   f'{json.dumps(self.telemetry.status, indent=4)}')
        status_current_time = self.telemetry.status.get('current-time', '')
        del_attr: List = []

        self.logger.debug(f'send_heartbeat: status_current_time = {status_current_time} '
                          f'_delete_attributes = {_del_attr}  status = {status}')

        if not status_current_time:
            status = {'status-notes': ['NuvlaBox Telemetry is starting']}
            self.telemetry.status.update(status)

        else:
            if status_current_time <= self.past_status_time:
                status = {
                    'status-notes': status.get('status-notes', []) + [
                        'NuvlaBox telemetry is falling behind'],
                    'status': 'DEGRADED'
                }
                self.telemetry.status.update(status)
            else:
                del_attr = _del_attr

        if del_attr:
            self.logger.info(f'Deleting the following attributes from NuvlaBox Status: '
                             f'{", ".join(del_attr)}')

        try:
            resource: CimiResource = self.nuvlaedge_common.api().edit(
                self.nuvlaedge_status_id,
                data=status,
                select=del_attr)

            self.telemetry.status_on_nuvla.update(status)

        except:
            self.logger.error("Unable to update NuvlaBox status in Nuvla")
            raise

        self.past_status_time = status_current_time

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
                           self.infrastructure.container_runtime.job_engine_lite_image,)

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
        if not isinstance(response.get('jobs', []), list):
            self.logger.warning(f'Jobs received on format {response.get("jobs")} not '
                                f'compatible')
            return

        pull_jobs: List = response.get('jobs', [])
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
        Controls the main funnctionallities of the agent:
            1. Sending heartbeat
            2. Running pull jobs

        Returns:

        """
        # check telemetry and infrastructure running
        if not self.telemetry_thread or not self.telemetry_thread.is_alive():
            self.telemetry_thread = threading.Thread(target=self.telemetry.update_status,
                                                     daemon=True)
            self.telemetry_thread.start()

        response: Dict = self.send_heartbeat()

        self.handle_pull_jobs(response)

        if not self.infrastructure.is_alive():
            self.infrastructure = Infrastructure(self._DATA_VOLUME)
            self.infrastructure.start()
