#!/usr/bin/env python

"""dd_cleint.py: Introduces basic configuration into the DefectDojo"""

__author__      = "Dubravko Sever"
__copyright__   = "Copyright 2020"

import os, sys, logging
import requests
from os import listdir
from os.path import isfile, join
import yaml

host = os.environ.get('HOST')
password = os.environ.get('API_KEY')
user = os.environ.get('USER')
host = host+"/api/v2"
verify_cert = bool(os.environ.get('VERIFY_CERT',False))
loglevel = os.environ.get('LOG_LEVEL',logging.DEBUG)
yaml_folder = os.environ.get('YAML_FOLDER',"./yaml")

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
    logging.info(url)
    r = requests.post(url, headers=headers, data=data,verify=verify_cert)
    if not r.ok:
        logging.error("problem occoured {0}".format(r.status_code))
        return None
    else:
        logging.debug("Object returned {0}".format(r.text))
        return r.json()

"""
Creating product type
"""
def createProductType(name, critical_product,key_product):
    api_call = api_call = host + "/product_types/"




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
    loadYaml()
#    token = retriveToken()
