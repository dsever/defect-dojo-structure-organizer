#!/usr/bin/env python

"""dd_client.py: Introduces basic configuration into the DefectDojo"""

__author__ = "Dubravko Sever"
__copyright__ = "Copyright 2020"

import os
import sys
import logging
import requests
import pprint
from os import listdir
from os.path import isfile, join

import yaml
import json
from yamllint import linter
from yamllint.config import YamlLintConfig

host = os.environ.get('HOST')
logging.debug("Host: {0}".format(host))
password = os.environ.get('API_KEY')
user = os.environ.get('USER')
host = host + "/api/v2"
verify_cert = False
log_level = os.environ.get('LOG_LEVEL', logging.DEBUG)
yaml_folder = os.environ.get('YAML_FOLDER', "./yaml")
token = None

root = logging.getLogger()
root.setLevel(log_level)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)


def get_token() -> str:
    """
    Collecting token from the server for gien user
    :return:
    """
    logging.info('Collecting api token')
    api_call = host + "/api-token-auth/"
    headers = {'accept': 'application/json'}
    data = {'username': user, 'password': password}
    ret_val = send_post_request(api_call, headers=headers, data=data)
    if ret_val is None:
        sys.exit(1)
    logging.debug("Returning token")
    return ret_val["token"]


def send_post_request(url, headers, data):
    """
    Sending post request
    :param url:
    :param headers:
    :param data:
    :return:
    """
    logging.info("Calling url {0}".format(url))
    r = requests.post(url, headers=headers, data=data, verify=verify_cert)
    if not r.ok:
        logging.error("Problem detected {0}".format(r.status_code))
        logging.debug("Item received {0}".format(r.headers))
        return None
    else:
        logging.debug("Object returned {0}".format(r.text))
        return r.json()


def send_get_request(url, headers):
    """
    Sending get request
    :param url:
    :param headers:
    :return:
    """
    r = requests.get(url, headers=headers, verify=verify_cert)
    if not r.ok:
        logging.error("Problem detected {0}".format(r.status_code))
        logging.debug("Item received {0}".format(r.headers))
        return None
    else:
        logging.debug("Object returned {0}".format(r.text))
        return r.json()


def create_product_types(product_types):
    """
    Creating product type
    """
    api_call = host + "/product_types/"
    headers = get_header()
    for product_type in product_types:
        logging.info("Creating product type: {0}".format(product_type))
        data = json.dumps(product_type)
        pprint.pprint(data)
        send_post_request(api_call, headers, data)


def get_header():
    """
    Generates request header
    """
    headers = {
        "Authorization": "Token {0}".format(token),
        "content-type": "application/json",
        "Content-Type": "application/json"
    }
    return headers


def create_development_environments(development_environments):
    logging.info("Creating development_environments")
    existing_env_list = []
    api_call = host + "/development_environments/"
    headers = get_header()
    existing_env = send_get_request(api_call, headers)
    logging.info("Existing Environments {0}".format(existing_env["results"]))
    for item in existing_env["results"]:
        existing_env_list.append(item["name"])
    print(existing_env_list)
    for env in development_environments:
        if env["name"] in existing_env_list:
            logging.info("Already exists {0}".format(env))
            continue
        data = json.dumps(env)
        send_post_request(api_call, headers, data)


def load_yaml():
    """
    Loads yaml file from the dictionary
    :return:
    """
    # yamlconfig = YamlLintConfig(file='./default.yaml')
    # for item in linter.run(yaml_folder, conf=yamlconfig):
    #     pprint.pprint(item)




    to_ret = {}

    only_files = [f for f in listdir(yaml_folder) if isfile(join(yaml_folder, f))]

    for item in only_files:
        file_path = yaml_folder + "/" + item
        print(file_path)
        with open(file_path) as f:
            to_ret.update(yaml.load(f, Loader=yaml.FullLoader))
    return to_ret


if __name__ == '__main__':
    logging.info("Checking certificate {0}".format(verify_cert))
    yaml_val = load_yaml()
    token = os.environ.get('API_KEY')
    for key in yaml_val.keys():
        logging.info(" key {0}", format(key))
        if key == "product_types":
            logging.info(yaml_val[key])
            create_product_types(yaml_val[key])
        if key == "development_environments":
            logging.info(yaml_val[key])
            create_development_environments(yaml_val[key])
