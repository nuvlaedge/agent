#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Agent API

List of functions to support the NuvlaBox Agent API instantiated by app.py
"""

import json
import logging
import os
import glob
import socket
import nuvla.api

from agent.common import NuvlaBoxCommon

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


def local_peripheral_save(filepath, content):
    """ Create a local file copy of the Nuvla peripheral resource

    :param filepath: path of the file to be written in the .peripherals folder
    :param content: content of the file in JSON format
    """

    with open(filepath, 'w') as f:
        f.write(json.dumps(content))


def local_peripheral_update(filepath, new_content):
    """ Create a local file copy of the Nuvla peripheral resource

    :param filepath: path of the file to be written in the .peripherals folder
    :param new_content: updated content of the file in JSON format
    """

    with open(filepath) as f:
        peripheral = json.loads(f.read())

    peripheral.update(new_content)

    with open(filepath, 'w') as f:
        f.write(json.dumps(peripheral))


def local_peripheral_get_identifier(filepath):
    """ Reads the content of a local copy of the NB peripheral, and gets the Nuvla ID

    :param filepath: path of the peripheral file in .peripherals, to be read
    :returns ID
    """

    try:
        with open(filepath) as f:
            peripheral_nuvla_id = json.loads(f.read())["id"]
    except:
        # if something happens, just return None
        return None

    return peripheral_nuvla_id


def post(payload):
    """ Creates a new nuvlabox-peripheral resource in Nuvla

    :param payload: base JSON payload for the nuvlabox-peripheral resource
    :returns request message and status
    """

    if not payload or not isinstance(payload, dict):
        # Invalid payload
        logging.error("Payload {} malformed. It must be a JSON payload".format(payload))
        return {"error": "Payload {} malformed. It must be a JSON payload".format(payload)}, 400

    try:
        peripheral_identifier = payload['identifier']
    except KeyError as e:
        logging.error("Payload {} is incomplete. Missing 'identifier'. {}".format(payload, e))
        return {"error": "Payload {} is incomplete. Missing 'identifier'. {}".format(payload, e)}, 400

    peripheral_filepath = "{}/{}".format(NB.peripherals_dir, peripheral_identifier)

    # Check if peripheral already exists locally before pushing to Nuvla
    if local_peripheral_exists(peripheral_filepath):
        logging.error("Peripheral %s file already registered. Please delete it first" % peripheral_identifier)
        return {"error": "Peripheral %s file already registered. Please delete it first" % peripheral_identifier}, 400

    # complete the payload with the NB specific attributes, in case they are missing
    if 'parent' not in payload:
        payload['parent'] = NB.nuvlabox_id

    if 'version' not in payload:
        if os.path.exists("{}/{}".format(NB.data_volume, NB.context)):
            version = json.loads(open("{}/{}".format(NB.data_volume, NB.context)).read())['version']
        else:
            try:
                tag = NB.docker_client.api.inspect_container(socket.gethostname())['Config']['Labels']['git.branch']
                version = int(tag.split('.')[0])
            except (KeyError, ValueError, IndexError):
                version = 1

        payload['version'] = version

    # check if it already exists in Nuvla
    try:
        existing_nuvla_per = NB.api().get('nuvlabox-peripheral', filter=f'identifier="{peripheral_identifier}"').data
    except nuvla.api.api.NuvlaError as e:
        logging.exception("Unable to reach Nuvla")
        return e.response.json(), e.response.status_code

    if existing_nuvla_per.get('count', 0) > 0:
        # already registered in Nuvla, but not locally...maybe something went wrong in a past mgmt action
        # let's just update it
        fix_edit = modify(peripheral_identifier,
                          peripheral_nuvla_id=existing_nuvla_per['resources'][0]['id'],
                          payload=payload)

        if fix_edit[1] == 200:
            fix_edit[0]['id'] = existing_nuvla_per['resources'][0]['id']
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
        logging.exception("Unable to save peripheral. Reverting request...")
        modify(peripheral_identifier, peripheral_nuvla_id=payload['id'], action='DELETE')
        return {"error": "Unable to fulfill request: %s" % e}, 500

    return new_peripheral.data, new_peripheral.data['status']


def modify(peripheral_identifier, peripheral_nuvla_id=None, action='PUT', payload=None):
    """ Modifies (edits or deletes) a peripheral from the local and Nuvla database

    :param peripheral_identifier: unique local identifier for the peripheral
    :param peripheral_nuvla_id: (optional) Nuvla ID for the peripheral resource. If present, will not infer it from
    the local file copy of the peripheral resource
    :param action: PUT or DELETE
    :param payload: body used for PUT
    :returns request message and status
    """

    if action not in ["DELETE", "PUT"]:
        msg = f'Method {action} not supported'
        logging.error(msg)
        return {"error": msg}, 405

    peripheral_filepath = "{}/{}".format(NB.peripherals_dir, peripheral_identifier)

    if not local_peripheral_exists(peripheral_filepath):
        # local peripheral file does not exist, let's check in Nuvla
        logging.info("{} does not exist locally. Checking in Nuvla...".format(peripheral_filepath))
        if peripheral_nuvla_id:
            try:
                if action == 'DELETE':
                    out_peripheral = NB.api().delete(peripheral_nuvla_id)
                    logging.info("Deleted {} from Nuvla".format(peripheral_nuvla_id))
                else:
                    out_peripheral = NB.api().edit(peripheral_nuvla_id, payload)
                    logging.info("Changed {} in Nuvla, with payload: {}".format(peripheral_nuvla_id, payload))
                return out_peripheral.data, out_peripheral.data.get('status', 200)
            except nuvla.api.api.NuvlaError as e:
                logging.warning("Cannot {} {} in Nuvla: {}".format(action, peripheral_nuvla_id, e.response.json()))
                return e.response.json(), e.response.status_code
        else:
            logging.warning("{} not found and Nuvla resource ID not provided".format(peripheral_filepath))
            return {"error": "Peripheral not found"}, 404
    else:
        # file exists, but before changing it, check if we need to infer the Nuvla ID from it
        if not peripheral_nuvla_id:
            peripheral_nuvla_id = local_peripheral_get_identifier(peripheral_filepath)

        if peripheral_nuvla_id:
            try:
                if action == 'DELETE':
                    out_peripheral = NB.api().delete(peripheral_nuvla_id)
                    os.remove(peripheral_filepath)
                    logging.info("Deleted {} from Nuvla".format(peripheral_nuvla_id))
                else:
                    out_peripheral = NB.api().edit(peripheral_nuvla_id, payload)
                    local_peripheral_update(peripheral_filepath, payload)
                    logging.info("Changed {} in Nuvla, with payload: {}".format(peripheral_nuvla_id, payload))

                return out_peripheral.data, out_peripheral.data.get('status', 200)
            except nuvla.api.api.NuvlaError as e:
                if e.response.status_code != 404:
                    logging.warning("While running {} on {} from Nuvla: {}".format(action,
                                                                                   peripheral_nuvla_id,
                                                                                   e.response.json()))
                    # Maybe something went wrong and we should try later, so keep the local peripheral copy alive
                    return e.response.json(), e.response.status_code
                else:
                    if action == 'DELETE':
                        # Even if the peripheral does not exist in Nuvla anymore, let's delete it locally
                        os.remove(peripheral_filepath)
                        logging.info("Deleted {} from the NuvlaBox".format(peripheral_filepath))
                        return {"message": "Deleted %s" % peripheral_identifier}, 200
            except Exception as e:
                # for any other deletion problem, report
                logging.exception("While running {} on {} from Nuvla".format(action, peripheral_nuvla_id))
                return {"error": "Error occurred while deleting {}: {}".format(peripheral_identifier, e)}, 500


def find(parameter, value, identifier_pattern):
    """ Finds all locally registered peripherals that match parameter=value

    :param parameter: name of the parameter to search for
    :param value: value of that parameter
    :param identifier_pattern: regex expression to limit the search query to peripherals matching the identifier pattern
    :returns list of peripheral matching the search query
    """

    matched_peripherals = {}

    search_dir = "{}/{}".format(NB.peripherals_dir, identifier_pattern) if identifier_pattern \
        else NB.peripherals_dir + "/**/**"

    for filename in glob.iglob(search_dir, recursive=True):
        if os.path.isdir(filename):
            continue

        with open(filename) as f:
            try:
                content = json.loads(f.read())
            except:
                continue

        if parameter and value:
            if parameter in content and content[parameter] == value:
                matched_peripherals[filename.replace(f'{NB.peripherals_dir}/', '')] = content
        else:
            matched_peripherals[filename.replace(f'{NB.peripherals_dir}/', '')] = content

    return matched_peripherals, 200


def get(identifier):
    """ Finds a specific locally registered peripherals that matches the identifier, by filename

    :param identifier: peripheral identifier and filename (including its subfolder if any)
    :returns peripheral content
    """

    search_for = "{}/{}".format(NB.peripherals_dir, identifier)

    if local_peripheral_exists(search_for):
        with open(search_for) as p:
            try:
                return json.loads(p.read()), 200
            except:
                return {"error": "Cannot read peripheral information"}, 500
    else:
        return {"error": "Peripheral not found"}, 404

