from mock import Mock, MagicMock, patch

import agent.common.NuvlaBoxCommon
import tests.utils.fake as fake
import unittest

from agent import Agent
from agent.common import NuvlaBoxCommon


class TestAgent(unittest.TestCase):
    agent_flag = True

    def setUp(self):
        with patch(agent.common.NuvlaBoxCommon.NuvlaBoxCommon) as mock_nuvlaedgecom:
            mock_nuvlaedgecom.return_value = Mock()
            self.agent = Agent(self.agent_flag)


    def test_init(self):
        mock_flag = True
        mock_agent: Agent = Agent(mock_flag)
        self.assertTrue(mock_agent.agent_flag)
        self.assertIsNotNone(mock_agent.nuvlaedge_common)
        self.assertIsNotNone(mock_agent.infrastructure)
