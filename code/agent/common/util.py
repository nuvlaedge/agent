"""
This file gathers general utilities demanded by most of the classes such as a command executor
"""
import logging

from typing import List, Union, Dict
from subprocess import (Popen, run, PIPE, TimeoutExpired,
                        SubprocessError, STDOUT, CompletedProcess)


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
