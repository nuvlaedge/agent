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
        else:
            p = Popen(command, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate()
            return {'stdout': stdout, 'stderr': stderr, 'returncode': p.returncode}

    except OSError as osErr:
        logging.error(f"Trying to execute non existent file: {osErr}")

    except ValueError as valErr:
        logging.error(f"Invalid arguments executed: {valErr}")

    except TimeoutExpired as timErr:
        logging.error(f"Timeout {timErr} expired waiting for command: {command}")

    except SubprocessError as generalErr:
        logging.error(f"Exception not identified: {generalErr}")
    return None