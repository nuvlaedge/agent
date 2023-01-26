import os

from agent import Agent
from mock import Mock, patch
from unittest import TestCase


class TestAgent(TestCase):
    agent_open: str = 'agent.agent.open'
    atomic_write: str = 'agent.common.util.atomic_write'

    @patch('agent.agent.NuvlaEdgeCommon')
    @patch('agent.agent.Activate')
    def setUp(self, nb_mock, activate_mock) -> None:
        os.environ['COMPOSE_PROJECT'] = 'tests'
        self.test_agent: Agent = Agent(True)

    @patch('threading.Event.wait')
    def test_activate_nuvlaedge(self, wait_mock):
        self.test_agent.activate.activation_is_possible.side_effect =\
            [(False, None), (True, None)]

        self.test_agent.activate.update_nuvlaedge_resource.return_value = \
            ({'nuvlabox-status': 1}, None)
        self.test_agent.activate_nuvlaedge()
        self.assertEqual(self.test_agent.activate.activation_is_possible.call_count, 2)
        self.assertEqual(self.test_agent.activate.update_nuvlaedge_resource.call_count, 1)
        self.assertEqual(self.test_agent.activate.vpn_commission_if_needed.call_count, 1)
        self.assertEqual(wait_mock.call_count, 1)

    @patch('agent.agent.Infrastructure')
    def test_initialize_infrastructure(self, infra_mock):
        it_mock = Mock()
        it_mock.installation_home = True
        infra_mock.return_value = it_mock
        with patch(self.agent_open) as mock_open, patch(self.atomic_write):
            self.test_agent.initialize_infrastructure()
            # TODO: fix
            # self.assertEqual(mock_open.call_count, 1)

    @patch('os.environ.get')
    @patch('agent.agent.Telemetry')
    def test_initialize_telemetry(self, tel_mock, env_patch):
        self.test_agent.initialize_telemetry()
        self.assertEqual(tel_mock.call_count, 1)
        self.assertEqual(env_patch.call_count, 1)

    @patch('agent.agent.Agent.activate_nuvlaedge')
    @patch('agent.agent.Agent.initialize_telemetry')
    @patch('agent.agent.Agent.initialize_infrastructure')
    def test_initialize_agent(self, infra_mock, tel_mock, act_mock):
        self.assertTrue(self.test_agent.initialize_agent())
        infra_mock.assert_called_once()
        tel_mock.assert_called_once()
        act_mock.assert_called_once()

    def test_send_heartbeat(self):
        tel_mock = Mock()
        tel_mock.diff.return_value = ({}, ['a'])
        tel_mock.status.get.return_value = ''
        self.test_agent.telemetry = tel_mock
        self.test_agent.send_heartbeat()
        self.assertEqual(tel_mock.status.update.call_count, 1)

        tel_mock.status.update.reset_mock()
        tel_mock.status.get.return_value = 1
        self.test_agent.past_status_time = 2
        api_mock = Mock()
        ret_mock = Mock()
        ret_mock.data = "ret"
        api_mock.edit.return_value = ret_mock
        self.test_agent.nuvlaedge_common.api.return_value = api_mock
        self.assertEqual(self.test_agent.send_heartbeat(), "ret")
        self.assertEqual(tel_mock.status.update.call_count, 1)
        self.assertEqual(api_mock.edit.call_count, 1)

        self.test_agent.nuvlaedge_common.api.side_effect = OSError
        with self.assertRaises(OSError):
            self.test_agent.send_heartbeat()

    @patch('agent.agent.Job')
    @patch('agent.job.Job.launch')
    def test_run_pull_jobs(self, mock_launch, mock_job):
        self.test_agent.run_pull_jobs([])
        self.assertEqual(mock_job.call_count, 0)

        infra_mock = Mock()
        self.test_agent.infrastructure = infra_mock
        self.test_agent.run_pull_jobs(['1'])
        self.assertEqual(mock_job.call_count, 1)
        self.assertEqual(mock_launch.call_count, 0)

        it_mock = Mock()
        it_mock.do_nothing = False
        it_mock.launch.return_value = "None"
        mock_job.return_value = it_mock
        self.test_agent.run_pull_jobs(['1'])
        self.assertEqual(it_mock.launch.call_count, 1)

    @patch('agent.agent.Infrastructure')
    @patch('agent.agent.threading.Thread.start')
    def test_handle_pull_jobs(self, mock_thread, infra_mock):
        infra_mock.container_runtime.job_engine_lite_image = True
        self.test_agent.infrastructure = infra_mock
        self.test_agent.handle_pull_jobs({'jobs': ['1', '2']})
        mock_thread.assert_called_once()
        mock_thread.reset_mock()

        infra_mock.container_runtime.job_engine_lite_image = False
        self.test_agent.handle_pull_jobs({})
        self.assertEqual(mock_thread.call_count, 0)

        with patch('logging.Logger.warning') as mock_warn:
            self.test_agent.handle_pull_jobs({'jobs': 'PI'})
            mock_warn.assert_called_once()

    @patch('agent.agent.Agent.send_heartbeat')
    @patch('agent.agent.Agent.handle_pull_jobs')
    @patch('threading.Thread.start')
    @patch('agent.agent.Infrastructure')
    def test_run_single_cycle(self, inf_mock, mock_start, pull_mock, mock_beat):
        self.test_agent.telemetry_thread = False
        self.test_agent.telemetry = Mock()
        self.test_agent.infrastructure = Mock()
        self.test_agent.run_single_cycle()
        mock_start.assert_called_once()
        pull_mock.assert_called_once()

        mock_beat.return_value = {'jobs': []}
        infra_mock = Mock()
        infra_mock.is_alive.return_value = False
        infra_mock.start.return_value = None
        self.test_agent.infrastructure = infra_mock
        self.test_agent.run_single_cycle()
        self.test_agent.infrastructure.start.assert_called_once()
