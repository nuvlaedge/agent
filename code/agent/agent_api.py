#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Agent API

List of functions to support the NuvlaBox Agent API instantiated by app.py
"""

import json
import logging
import os
import glob
import nuvla.api

from agent.common import NuvlaBoxCommon, util

nuvla_resource = "nuvlabox-peripheral"
NB = NuvlaBoxCommon.NuvlaBoxCommon()


def local_peripheral_exists(filepath):
    """ Check if a local file copy of the Nuvla peripheral resource already exists

    :param filepath: path of the file in the .peripherals folder
    :returns boolean
    """
    if os.path.exists(filepath):
        return True

    return False


def local_peripheral_save(filepath: str, content: dict):
    """ Create a local file copy of the Nuvla peripheral resource

    :param filepath: path of the file to be written in the .peripherals folder
    :param content: content of the file in JSON format
    """
    NB.write_json_to_file(filepath, content)


def local_peripheral_update(filepath: str, new_content: dict):
    """ Create a local file copy of the Nuvla peripheral resource

    :param filepath: path of the file to be written in the .peripherals folder
    :param new_content: updated content of the file in JSON format
    """
    peripheral = NB.read_json_file(filepath)

    peripheral.update(new_content)

    NB.write_json_to_file(filepath, peripheral)


def local_peripheral_get_identifier(filepath):
    """ Reads the content of a local copy of the NB peripheral, and gets the Nuvla ID

    :param filepath: path of the peripheral file in .peripherals, to be read
    :returns ID
    """
    try:
        peripheral_nuvla_id = NB.read_json_file(filepath)["id"]
    except (KeyError, FileNotFoundError):
        # if something happens, just return None
        return None

    return peripheral_nuvla_id


def sanitize_peripheral_payload(payload: dict):
    """
    Validates, completes and prepares the peripheral payload to be sent to Nuvla

    :param payload: peripheral body for the Nuvla request
    :return:
    """
    # this shall throw an exception in case the payload is not structured as expected
    _ = payload['identifier']

    # complete the payload with the NB specific attributes, in case they are missing
    payload['parent'] = NB.nuvlabox_id
    payload['version'] = NB.get_nuvlabox_version()


def post(payload):
    """ Creates a new nuvlabox-peripheral resource in Nuvla

    :param payload: base JSON payload for the nuvlabox-peripheral resource
    :returns request message and status
    """
    try:
        sanitize_peripheral_payload(payload)
    except KeyError as e:
        logging.error(f"Payload {payload} is incomplete. Missing 'identifier'. {e}")
        return {"error": f"Payload {payload} is incomplete. Missing "
                         f"'identifier'. {e}"}, 400
    except TypeError:
        logging.error("Payload {} malformed. It must be a JSON payload".format(payload))
        return {"error":f"Payload {payload} malformed. It must be a JSON payload"}, 400

    peripheral_identifier = payload['identifier']
    peripheral_filepath = "{}/{}".format(NB.peripherals_dir, peripheral_identifier)

    # Check if peripheral already exists locally before pushing to Nuvla
    if local_peripheral_exists(peripheral_filepath):
        logging.error(f"Peripheral {peripheral_identifier} file already registered. "
                      f"Please delete it first")
        return {f"error": f"Peripheral {peripheral_identifier} file already registered."
                          f" Please delete it first"}, 400

    # check if it already exists in Nuvla
    try:
        existing_nuvla_per = NB.api().get(
            'nuvlabox-peripheral',
            filter=f'identifier="{peripheral_identifier}"').data

    except nuvla.api.api.NuvlaError as e:
        logging.exception("Unable to reach Nuvla")
        return e.response.json(), e.response.status_code

    if existing_nuvla_per.get('count', 0) > 0:
        # already registered in Nuvla, but not locally...maybe something went wrong in a
        # past mgmt action let's just update it
        fix_edit = modify(peripheral_identifier,
                          peripheral_nuvla_id=existing_nuvla_per['resources'][0]['id'],
                          payload=payload)

        if fix_edit[1] == 200:
            fix_edit[0]['resource-id'] = existing_nuvla_per['resources'][0]['id']
            payload['id'] = existing_nuvla_per['resources'][0]['id']
            local_peripheral_save(peripheral_filepath, payload)
            return fix_edit[0], 201

        return fix_edit

    # else
    # Try to POST the resource
    try:
        logging.info("Posting peripheral {}".format(payload))
        new_peripheral = NB.api().add(nuvla_resource, payload)
    except nuvla.api.api.NuvlaError as e:
        logging.exception("Failed to POST peripheral")
        return e.response.json(), e.response.status_code
    except Exception as e:
        logging.exception("Unable to POST peripheral to Nuvla")
        return {"error": "Unable to complete POST request: {}".format(e)}, 500

    payload['id'] = new_peripheral.data['resource-id']

    try:
        logging.info("Saving peripheral %s locally" % payload['id'])
        local_peripheral_save(peripheral_filepath, payload)
    except Exception as e:
        logging.error("Unable to save peripheral. Reverting request...")
        modify(peripheral_identifier, peripheral_nuvla_id=payload['id'], action='DELETE')
        return {"error": "Unable to fulfill request: %s" % e}, 500

    return new_peripheral.data, new_peripheral.data['status']


def modify(peripheral_identifier, peripheral_nuvla_id=None, action='PUT', payload=None):
    """ Modifies (edits or deletes) a peripheral from the local and Nuvla database

    :param peripheral_identifier: unique local identifier for the peripheral
    :param peripheral_nuvla_id: (optional) Nuvla ID for the peripheral resource.
    If present, will not infer it from the local file copy of the peripheral resource
    :param action: PUT or DELETE
    :param payload: body used for PUT
    :returns request message and status
    """

    if action not in ["DELETE", "PUT"]:
        msg = f'Method {action} not supported'
        logging.error(msg)
        return {"error": msg}, 405

    peripheral_filepath = "{}/{}".format(NB.peripherals_dir, peripheral_identifier)

    per_nuvla_id = peripheral_nuvla_id if peripheral_nuvla_id else \
        local_peripheral_get_identifier(peripheral_filepath)

    if not per_nuvla_id:
        logging.warning(f"{peripheral_filepath} not found and Nuvla resource ID not "
                        f"provided")
        return {"error": "Peripheral not found"}, 404

    try:
        if action == 'DELETE':
            out_peripheral = delete_peripheral(per_nuvla_id, peripheral_filepath)
            logging.info(f"Deleted {per_nuvla_id} from Nuvla")
        else:
            out_peripheral = edit_peripheral(per_nuvla_id, payload, peripheral_filepath)
            logging.info(f"Changed {per_nuvla_id} in Nuvla, with payload: {payload}")

        return out_peripheral.data, out_peripheral.data.get('status', 200)

    except nuvla.api.api.NuvlaError as e:
        if e.response.status_code == 404 and action == 'DELETE':
            logging.warning(f"Peripheral {per_nuvla_id} not found in Nuvla: "
                            f"{e.response.json()}")

            try:
                os.remove(peripheral_filepath)
            except FileNotFoundError:
                pass
            logging.info("Deleted {} from the NuvlaBox".format(peripheral_filepath))
            return {"message": f"Deleted {peripheral_identifier}"}, 200

        # Maybe something went wrong, and we should try later, so keep the local
        # peripheral copy alive
        logging.warning(f"Cannot {action} {peripheral_nuvla_id} in "
                        f"Nuvla: {e.response.json()}")
        return e.response.json(), e.response.status_code

    except Exception as e:
        logging.exception(f"While running {action} on {peripheral_nuvla_id} from Nuvla")
        return {"error": f"Error occurred while doing {action} on "
                         f"{peripheral_identifier}: {str(e)}"}, 500


def edit_peripheral(peripheral_id: str, body: dict, local_filepath: str) \
        -> nuvla.api.api.CimiResponse:
    """
    Edits a peripheral in Nuvla and locally if needed

    :param peripheral_id: Nuvla ID of the peripheral
    :param body: new peripheral content
    :param local_filepath: local peripheral file path
    :return: Nuvla response to the edit request
    """
    response = NB.api().edit(peripheral_id, body)
    if local_peripheral_exists(local_filepath):
        local_peripheral_update(local_filepath, body)

    return response


def delete_peripheral(peripheral_id: str, local_filepath: str) \
        -> nuvla.api.api.CimiResponse:
    """
    Deletes a peripheral from Nuvla and locally as well

    Args:
        peripheral_id (str): Nuvla ID of the peripheral
        local_filepath (str): local peripheral file path

    Returns: Nuvla response to the delete request
    """
    response = NB.api().delete(peripheral_id)
    if local_peripheral_exists(local_filepath):
        os.remove(local_filepath)

    return response


def find(parameter, value, identifier_pattern):
    """ Finds all locally registered peripherals that match parameter=value

    :param parameter: name of the parameter to search for
    :param value: value of that parameter
    :param identifier_pattern: regex expression to limit the search query to peripherals
    matching the identifier pattern
    :returns list of peripheral matching the search query
    """
    matched_peripherals = {}

    search_dir = "{}/{}".format(NB.peripherals_dir, identifier_pattern) \
        if identifier_pattern else NB.peripherals_dir + "/**/**"

    for filename in glob.iglob(search_dir, recursive=True):
        if os.path.isdir(filename):
            continue

        with open(filename) as f:
            try:
                content = json.loads(f.read())
            except (json.JSONDecodeError, IOError):
                continue

        if parameter and value:
            if parameter in content and content[parameter] == value:
                matched_peripherals[filename.replace(f'{NB.peripherals_dir}/', '')] = \
                    content
        else:
            matched_peripherals[filename.replace(f'{NB.peripherals_dir}/', '')] = content

    return matched_peripherals, 200


def get(identifier):
    """ Finds a specific locally registered peripherals that matches the identifier, by
    filename

    :param identifier: peripheral identifier and filename(including its sub folder if any)
    :returns peripheral content
    """
    search_for = "{}/{}".format(NB.peripherals_dir, identifier)

    if local_peripheral_exists(search_for):
        with open(search_for) as p:
            try:
                return json.loads(p.read()), 200
            except (json.JSONDecodeError, IOError):
                return {"error": "Cannot read peripheral information"}, 500
    else:
        return {"error": "Peripheral not found"}, 404


def save_vpn_ip(ip):
    """
    Take the IP as a string and writes it into the shared volume

    :param ip: string
    :return:
    """
    util.atomic_write(NB.vpn_ip_file, str(ip))


def save_vulnerabilities(vulnerabilities):
    """
    Dumps vulnerabilities into a file

    :param vulnerabilities: as JSON
    :return:
    """
    util.atomic_write(NB.vulnerabilities_file, json.dumps(vulnerabilities))
