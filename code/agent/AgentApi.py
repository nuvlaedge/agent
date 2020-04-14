#!/usr/local/bin/python3.7
# -*- coding: utf-8 -*-

""" NuvlaBox Agent API

List of functions to support the NuvlaBox Agent API instantiated by app.py
"""

import json
import logging
import os
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
    :param content: content of the file (normally JSON)
    """

    with open(filepath, 'w') as f:
        f.write(content)


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
        return "Payload {} malformed. It must be a JSON payload".format(payload), 400

    try:
        peripheral_identifier = payload['identifier']
    except KeyError as e:
        return "Payload {} is incomplete. Missing 'identifier'. {}".format(payload, e), 400

    peripheral_filepath = "{}/{}".format(NB.peripherals_dir, peripheral_identifier)

    # Check if peripheral already exists locally before pushing to Nuvla
    if local_peripheral_exists(peripheral_filepath):
        return "Peripheral %s file already registered. Please delete it first" % peripheral_identifier, 400

    # Try to POST the resource
    try:
        new_peripheral = NB.api().add(nuvla_resource, payload)
    except nuvla.api.api.NuvlaError as e:
        return e.response.json(), e.response.status_code
    except Exception as e:
        return "Unable to complete POST request: {}".format(e), 500

    payload['id'] = new_peripheral.data['resource-id']

    try:
        local_peripheral_save(peripheral_filepath, payload)
    except Exception as e:
        delete(peripheral_identifier, peripheral_nuvla_id=payload['id'])
        return "Unable to fulfill request: %s" % e, 500

    return new_peripheral.data, new_peripheral.data['status']


def delete(peripheral_identifier, peripheral_nuvla_id=None):
    """ Deletes a peripheral from the local and Nuvla database

    :param peripheral_identifier: unique local identifier for the peripheral
    :param peripheral_nuvla_id: (optional) Nuvla ID for the peripheral resource. If present, will not infer it from
    the local file copy of the peripheral resource
    :returns request message and status
    """

    peripheral_filepath = "{}/{}".format(NB.peripherals_dir, peripheral_identifier)

    if not local_peripheral_exists(peripheral_filepath):
        # local peripheral file does not exist, let's check in Nuvla
        logging.info("{} does not exist locally. Checking in Nuvla...".format(peripheral_filepath))
        if peripheral_nuvla_id:
            try:
                delete_peripheral = NB.api().delete(peripheral_nuvla_id)
                logging.info("Deleted {} from Nuvla".format(peripheral_nuvla_id))
                return delete_peripheral.data, delete_peripheral.data['status']
            except nuvla.api.api.NuvlaError as e:
                logging.warning("While deleting {} from Nuvla: {}".format(peripheral_nuvla_id, e.response.json()))
                return e.response.json(), e.response.status_code
        else:
            logging.warning("{} and {} not found".format(peripheral_filepath, peripheral_nuvla_id))
            return "Peripheral not found", 404
    else:
        # file exists, but before deleting it, check if we need to infer the Nuvla ID from it
        if not peripheral_nuvla_id:
            peripheral_nuvla_id = local_peripheral_get_identifier(peripheral_filepath)

        if peripheral_nuvla_id:
            try:
                delete_peripheral = NB.api().delete(peripheral_nuvla_id)
                logging.info("Deleted {} from Nuvla".format(peripheral_nuvla_id))

                os.remove(peripheral_filepath)
                logging.info("Deleted {} from the NuvlaBox".format(peripheral_filepath))

                return delete_peripheral.data, delete_peripheral.data['status']
            except nuvla.api.api.NuvlaError as e:
                if e.response.status_code != 404:
                    logging.warning("While deleting {} from Nuvla: {}".format(peripheral_nuvla_id, e.response.json()))
                    # Maybe something went wrong and we should try later, so keep the local peripheral copy alive
                    return e.response.json(), e.response.status_code
            except Exception as e:
                # for any other deletion problem, report
                logging.exception("While deleting {} from Nuvla".format(peripheral_nuvla_id))
                return "Error occurred while deleting {}: {}".format(peripheral_identifier, e), 500

        # Even if the peripheral does not exist in Nuvla anymore, let's delete it locally
        os.remove(peripheral_filepath)
        logging.info("Deleted {} from the NuvlaBox".format(peripheral_filepath))
        return "Deleted %s" % peripheral_identifier, 200


def find(parameter, value):
    """ Finds all locally registered peripherals that match parameter=value

    :param parameter: name of the parameter to search for
    :param value: value of that parameter
    :returns list of peripheral matching the search query
    """
    matched_peripherals = []

    for filename in os.listdir(NB.peripherals_dir):
        with open(NB.peripherals_dir + "/" + filename) as f:
            try:
                content = json.loads(f.read())
            except:
                continue

            if parameter in content and content[parameter] == value:
                matched_peripherals.append(filename)

    return matched_peripherals, 200

