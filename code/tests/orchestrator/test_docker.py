import mock
import requests
import unittest

from agent.orchestrator.docker import DockerClient


class Test(unittest.TestCase):

    def setUp(self) -> None:

        self.docker = DockerClient('foo', 'bar', check_docker_host=False)
        self.docker.client = mock.MagicMock()

    @mock.patch('requests.get')
    def test_compute_api_is_running(self, mock_get):

        # if compute-api is running, return True
        compute_api_container = mock.MagicMock()
        compute_api_container.status = 'stopped'
        self.docker.client.containers.get.return_value = compute_api_container
        self.assertFalse(self.docker.compute_api_is_running(''),
                         'Unable to detect that compute-api is not running')

        # if running, try to reach its API
        # if an exception occurs, return False
        compute_api_container.status = 'running'
        self.docker.client.containers.get.return_value = compute_api_container
        mock_get.side_effect = TimeoutError
        self.assertFalse(self.docker.compute_api_is_running(''),
                         'Assuming compute-api is running even though we could not assess that')
        mock_get.assert_called_once()
        # except if the exception is SSL related
        mock_get.side_effect = requests.exceptions.SSLError
        self.assertTrue(self.docker.compute_api_is_running(''),
                        'Unable to detect that compute-api is running')

