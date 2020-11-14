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
log_level = os.environ.get('LOG_LEVEL', logging.INFO)
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
    if (r.status_code >= 300):
        logging.error(r.text)
    return check_http_response(r)


def check_http_response(r):
    if not r.ok:
        logging.error("Problem detected Code: {0} Reason:{1}".format(r.status_code, r.reason))
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
    return check_http_response(r)


def product_types(product_types):
    """
    Creating product type
    """
    existing_prod_list = []
    headers = get_header()
    existing_env = send_get_request(api_call('product_types'), headers)
    logging.info("Existing product_types {0}".format(existing_env["results"]))
    for item in existing_env["results"]:
        existing_prod_list.append(item["name"])
    for product_type in product_types:
        if product_type["name"] in existing_prod_list:
            logging.info("Already exists {0}".format(product_type))
            continue
        logging.info("Creating product type: {0}".format(product_type))
        data = json.dumps(product_type)
        send_post_request(api_call('product_types'), headers, data)


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


def development_environments(development_environments):
    """
    Created new environemnt
    :param development_environments:
    :return:
    """
    logging.info("Creating development_environments")
    existing_env_list = []
    headers = get_header()
    existing_env = send_get_request(api_call('development_environments'), headers)
    logging.info("Existing Environments {0}".format(existing_env["results"]))
    for item in existing_env["results"]:
        existing_env_list.append(item["name"])
    print(existing_env_list)
    for env in development_environments:
        if env["name"] in existing_env_list:
            logging.info("Already exists {0}".format(env))
            continue
        data = json.dumps(env)
        send_post_request(api_call('development_environments'), headers, data)

def regulations(regulations):
    """
    Created new regulation
    :param regulations:
    :return:
    """
    logging.info("Creating regulations")
    existing_reg_list = []
    headers = get_header()
    existing_reg = send_get_request(api_call('regulations'), headers)
    #logging.info("Existing regulations {0}".format(existing_reg["results"]))
    for item in existing_reg["results"]:
        existing_reg_list.append(item["name"])
    logging.info("Existing regulation list {0}".format(existing_reg_list))
    for reg in regulations:
        if reg["name"] in existing_reg_list:
            logging.info("Already exists {0}".format(reg))
            continue
        pprint.pprint("reg {0}".format(reg))
        data = json.dumps(reg)
        pprint.pprint("Test {0}".format(data))
        send_post_request(api_call('regulations'), headers, data)


def users(users):
    """
    Created new regulation
    :param regulations:
    :return:
    """
    logging.info("Creating users")
    existing_user_list = []
    headers = get_header()
    existing_users = send_get_request(api_call('users'), headers)
    logging.info("Existing regulations {0}".format(existing_users["results"]))
    for item in existing_users["results"]:
        existing_user_list.append(item["username"])
    logging.info("Existing regulation list {0}".format(existing_user_list))
    for user in users:
        if user["username"] in existing_user_list:
            logging.info("Already exists user: {0}".format(user))
            continue
        data = json.dumps(user)
        send_post_request(api_call('users'), headers, data)


def get_user_id(user):
    """
    Get user id from username
    :param user:
    :return:
    """
    headers = get_header()
    existing_users = send_get_request(api_call('users'), headers)
    for _user in existing_users["results"]:
        if user in _user['username']:
            return _user['id']
    return None

def get_product_id(product):
    headers = get_header()
    existing_product = send_get_request(api_call('products'), headers)
    for _product in existing_product["results"]:
        if product in _product['name']:
            return _product['id']
    return None


def get_engagament_id(engagament):
    headers = get_header()
    existing_engagaments = send_get_request(api_call('engagements'), headers)
    for _engagament in existing_engagaments["results"]:
        if engagament in _engagament['name']:
            return _engagament['id']
    return None


def get_prod_type_id(product_type):
    headers = get_header()
    existing_product_types = send_get_request(api_call('product_types'), headers)
    for _product_type in existing_product_types["results"]:
        if product_type in _product_type['name']:
            return _product_type['id']
    return None


def api_call(method):
    return  (host + "/{0}/".format(method))


def products(products):
    existing_products_list = []
    logging.info("Creating products")
    headers = get_header()
    existing_products = send_get_request(api_call('products'), headers)
    for item in existing_products["results"]:
        existing_products_list.append(item['name'])
    for product in products:
        if "authorized_users" in product.keys():
            tmp_list = []
            for item in product["authorized_users"]:
                tmp_list.append(get_user_id(item))
            product["authorized_users"] = tmp_list
            product['prod_type'] = get_prod_type_id(product['prod_type'])
        data = json.dumps(product)
        send_post_request(api_call('products'), headers, data)


def engagements(engagements):
    existing_eng_list = []
    logging.info("Creating engagements")
    headers = get_header()
    existing_eng = send_get_request(api_call('engagements'), headers)
    for item in existing_eng["results"]:
        existing_eng_list.append({"name": item['name'], "product": item["product"]})
    logging.info("Existing engagaments {0}".format(existing_eng_list) )
    for eng in engagements:
        product_id = get_product_id(eng["product"])
        eng['product'] = product_id
        construct_dict= {"name": eng["name"], "product": product_id}
        if construct_dict in existing_eng_list:
            continue
        data = json.dumps(eng)
        print(data)
        send_post_request(api_call('engagements'), headers, data)

def import_scan(scans):
    logging.info("Uploading file")
    for scan in scans:
        scan['engagement']=get_engagament_id(scan['engagement'])
        files  = [
             ('file', open(scan['file'], 'rb'))
         ]
        headers = {
            "Authorization": "Token {0}".format(token)
        }
        r = requests.post(api_call("import-scan"), headers=headers, data = scan, files=files, verify=False )



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
            try:
                to_ret.update(yaml.load(f, Loader=yaml.FullLoader))
            except:
                continue
    return to_ret


if __name__ == '__main__':
    logging.info("Checking certificate {0}".format(verify_cert))
    yaml_val = load_yaml()
    token = os.environ.get('API_KEY')
    call_list= {}

    for key in yaml_val.keys():
        if key == "product_types":
            priority = 4
            logging.info(yaml_val[key])
            call_list[priority] = key

        if key == "development_environments":
            priority = 3
            logging.info(yaml_val[key])
            call_list[priority] = key
        if key == "regulations":
            priority = 1
            logging.info(yaml_val[key])
            call_list[priority] = key

        if key == "users":
            priority = 2
            logging.info(yaml_val[key])
            call_list[priority] = key

        if key == "products":
            priority = 5
            logging.info(yaml_val[key])
            call_list[priority] = key
        if key == "engagements":
            priority = 6
            logging.info(yaml_val[key])
            call_list[priority] = key

        if key == "import_scan":
            priority = 7
            logging.info(yaml_val[key])
            call_list[priority] = key

    for i in sorted (call_list.keys()):
        eval(call_list[i])(yaml_val[call_list[i]])
