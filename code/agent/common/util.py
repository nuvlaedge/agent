"""
This file gathers general utilities demanded by most of the classes such as a command executor
"""
import json
import logging
from pathlib import Path
from typing import List, Union, Dict
from subprocess import (Popen, run, PIPE, TimeoutExpired,
                        SubprocessError, STDOUT, CompletedProcess)

from agent.schemas.worker_config import WorkerConfig
from agent.common.constants import MS_CONFIG_PATH


def gather_config_from_component(component_name: str) -> WorkerConfig:
    """
    Takes the component file name and reconstructs the component configuration
    Args:
        component_name: component config file name

    Returns: A filled WorkerConfig schema with the essential informatioon for the given
    component

    """
    component_config_location: Path = MS_CONFIG_PATH / component_name
    if not component_config_location.exists():
        raise Exception(f'Component {component_name} does not have a configuration file'
                        f'in the expected location')

    with component_config_location.open('r') as file:
        return WorkerConfig.parse_obj(
            json.load(file)
        )


def execute_cmd(command: List[str], method_flag: bool = True) \
        -> Union[Dict, CompletedProcess, None]:
    """ Shell wrapper to execute a command

    @param command: command to execute
    @param method_flag: flag to witch between run and Popen command exection
    @return: all outputs
    """
    try:
        if method_flag:
            return run(command, stdout=PIPE, stderr=STDOUT, encoding='UTF-8')

        with Popen(command, stdout=PIPE, stderr=PIPE) as shell_pipe:
            stdout, stderr = shell_pipe.communicate()

            return {'stdout': stdout,
                    'stderr': stderr,
                    'returncode': shell_pipe.returncode}

    except OSError as ex:
        logging.error(f"Trying to execute non existent file: {ex}")

    except ValueError as ex:
        logging.error(f"Invalid arguments executed: {ex}")

    except TimeoutExpired as ex:
        logging.error(f"Timeout {ex} expired waiting for command: {command}")

    except SubprocessError as ex:
        logging.error(f"Exception not identified: {ex}")

    return None
