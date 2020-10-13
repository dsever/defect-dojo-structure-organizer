#!/usr/bin/env python

"""dd_cleint.py: Introduces basic configuration into the DefectDojo"""

__author__      = "Dubravko Sever"
__copyright__   = "Copyright 2020"

import os, sys, logging
import requests
from os import listdir
from os.path import isfile, join
import yaml, json

host = os.environ.get('HOST')
logging.debug("Host: {0}".format(host))
password = os.environ.get('API_KEY')
user = os.environ.get('USER')
host = host+"/api/v2"
verify_cert = False
loglevel = os.environ.get('LOG_LEVEL',logging.DEBUG)
yaml_folder = os.environ.get('YAML_FOLDER',"./yaml")
token = None




root = logging.getLogger()
root.setLevel(loglevel)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)


"""
Retrives token from server for given user
"""
def retriveToken():
    logging.info('Retriving api token')
    api_call = host + "/api-token-auth/"
    headers = {'accept': 'application/json'}
    data = {'username':user, 'password':password}
    object = sendPostRequest(api_call,headers=headers, data=data)
    if object == None:
        sys.exit(1)
    logging.debug("Returning token")
    return object["token"]

"""
Sending postmethod to server
"""
def sendPostRequest(url, headers, data):
    print(verify_cert)
    logging.info("Calling url {0}".format(url))
    r = requests.post(url, headers=headers, data=data,verify=verify_cert)
    if not r.ok:
        logging.error("problem occoured {0}".format(r.status_code))
        logging.debug("Item sended {0}".format(r.headers))
        return None
    else:
        logging.debug("Object returned {0}".format(r.text))
        return r.json()

"""
Creating product type
"""
def createProductTypes(product_types):
    api_call = api_call = host + "/product_types/"
    headers = {
              "Authorization": "Token {0}".format(token),
              "content-type": "application/json",
              "Content-Type": "application/json"
              }
    for product_type in product_types:
        logging.info("Creating product type: {0}".format(product_type))
        data = json.dumps(product_types[product_type])
        sendPostRequest(api_call, headers, data)

def createDevelopementEnvironments(developement_environments):
    logging.info("Creating development_environments")
    api_call = api_call = host + "/development_environments/"
    headers = {
              "Authorization": "Token {0}".format(token),
              "content-type": "application/json",
              "Content-Type": "application/json"
              }
    for env in developement_environments:
        logging.info("Environment product type: {0}".format(env))
        data = json.dumps(developement_environments[env])
        print(data)
        sendPostRequest(api_call, headers, data)


def sendGetRequest(url, req):
    r = requests.post(url, headers=req, verify=True)


"""
Loads yaml file into the dictionary
"""
def loadYaml():
    object = {}
    onlyfiles = [f for f in listdir(yaml_folder) if isfile(join(yaml_folder, f))]
    for item in onlyfiles:
        with open(yaml_folder+"/"+item) as f:
            object.update(yaml.load(f, Loader=yaml.FullLoader))
    return object


if __name__=='__main__':
    print(verify_cert)
    object = loadYaml()

    token = os.environ.get('API_KEY')

    for key in object.keys():
        print(key)
        if key == "product_types":
            logging.info(object[key])
            createProductTypes(object[key])
        if key == "development_environments":
            logging.info(object[key])
            createDevelopementEnvironments(object[key])
