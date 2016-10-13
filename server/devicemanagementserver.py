"""
Copyright (C) 2014, Jaguar Land Rover
This program is licensed under the terms and conditions of the
Mozilla Public License, version 2.0.  The full text of the 
Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
Maintainer: Rudolf Streif (rstreif@jaguarlandrover.com)
Author: David Thiriez (david.thiriez@p3-group.com)
Device Management / Remote services.
"""

import os, threading, base64
from dateutil import parser, tz
from urlparse import urlparse
import Queue
from rvijsonrpc import RVIJSONRPCServer
import json
import pytz, uuid
import time
import jsonrpclib
import jwt
import datetime

import hashlib
from OpenSSL.crypto import dump_publickey, load_publickey
from OpenSSL.crypto import FILETYPE_PEM

from django.conf import settings

import __init__
from __init__ import __RVI_LOGGER__ as rvi_logger

from devices.tasks import send_remote, send_all_requested_remotes

from devices.models import Device, Remote
from vehicles.models import Vehicle
from django.contrib.auth.models import User

from Crypto.PublicKey import RSA

# globals
package_queue = Queue.Queue()
SERVER_NAME = "Backend Device Management Server: "

signing_file = open("rsaprivkey.key", "r")
signing_key = RSA.importKey(signing_file.read())
signing_file.close()

url_vehicle = "38.129.64.42"
port_vehicle = 9876

# Certificate Services Callback Server
class DeviceManagementServer(threading.Thread):
    """
    RPC server thread responding to Remote callbacks from the RVI framework.
    i.e. create certificate and update certificate requests from the mobile app
    """

    def __init__(self, service_edge, callback_url, service_id):
        self.service_edge = service_edge
        self.service_id = service_id
        self.callback_url = callback_url
        threading.Thread.__init__(self)
        url = urlparse(self.callback_url)
        self.localServer =  RVIJSONRPCServer(addr=((url.hostname, url.port)), logRequests=False)
        self.register_services()

    def register_services(self):
        # register callback functions with RPC server
        self.localServer.register_function(create_remote, self.service_id + "/authorize_services")
        self.localServer.register_function(revoke_remote, self.service_id + "/revoke_authorization")
        # self.localServer.register_function(get_vehicles, self.service_id + "/get_vehicles")
        self.localServer.register_function(get_user_data, self.service_id + "/get_user_data")
        # self.localServer.register_function(set_user_data, self.service_id + "/set_use_data")
        # for veh in Vehicle.objects.all():
        #     self.localServer.register_function(get_remote, self.service_id + "/" + veh.veh_vin)
        self.localServer.register_function(request_creds, "/credential_management/request_credentials")
        # self.localServer.register_function(requestall_remote, self.service_id + "/authorize_services")

        # register services with RVI framework
        result = self.service_edge.register_service(service = self.service_id+'/authorize_services',
                                               network_address = self.callback_url)
        rvi_logger.info(SERVER_NAME + 'Registration: '
                        'Create service name: %s', result['service'])

        result = self.service_edge.register_service(service = self.service_id+'/revoke_authorization',
                                               network_address = self.callback_url)
        rvi_logger.info(SERVER_NAME + 'Registration: '
                        'Modify service name: %s', result['service'])

        # result = self.service_edge.register_service(service = self.service_id+'/get_vehicles',
        #                                        network_address = self.callback_url)
        # rvi_logger.info(SERVER_NAME + 'Registration: '
        #                 'Get Vehicles: %s', result['service'])

        result = self.service_edge.register_service(service = self.service_id+'/get_user_data',
                                               network_address = self.callback_url)
        rvi_logger.info(SERVER_NAME + 'Registration: '
                        'Get User Data: %s', result['service'])

        # result = self.service_edge.register_service(service = self.service_id+'/set_user_data',
        #                                        network_address = self.callback_url)
        # rvi_logger.info(SERVER_NAME + 'Registration: '
        #                 'Set User Data: %s', result['service'])

        # for veh in Vehicle.objects.all():
        #     result = self.service_edge.register_service(service = self.service_id + '/' + veh.veh_vin,
        #                                         network_address = self.callback_url)
        #     rvi_logger.info(SERVER_NAME + 'Registration: '
        #                     'Vehicle Found: %s', result['service'])

        result = self.service_edge.register_service(service = '/credential_management/request_credentials',
                                               network_address = self.callback_url)
        rvi_logger.info(SERVER_NAME + 'Registration: '
                        'Retrieve all existing service name: %s', result['service'])

    def run(self):
        self.localServer.serve_forever()

    def shutdown(self):
        self.localServer.shutdown()


# Callback functions
# def get_vehicles(node_identifier, public_key):

#     try:
#         nodeID = node_identifier.rsplit("/", 1)[-1]
#         dev, user = validate_device(nodeID)
#     except Exception:
#         rvi_logger.exception(SERVER_NAME + 'Received data did not pass validation')
#         return {u'status': 0}

#     vehs = Vehicle.objects.filter(account=user)
#     owner_vehs = []
#     for v in vehs:
#         owner_vehs.append({"vehicle_name" : v.veh_name, "veh_id" : v.veh_vin})

#     print(owner_vehs)
#     try:
#         rvi_server.message(
#             calling_service = "get_vehicles",
#             service_name = "genivi.org/android/{}/dm/get_vehicles".format(dev.dev_uuid),
#             transaction_id = str(int(time.time())),
#             timeout = int(time.time()) + 5000,
#             # parameters = {"credentials":[encoded_jwt]}
#             parameters = {"vehicle_list":owner_vehs}
#         )

#     except Exception as e:
#         logger.error('%s: Cannot connect to RVI service edge: %s', remote, e)
#         return False

def get_user_data(node_identifier):


    try:
        rvi_service_url = settings.RVI_SERVICE_EDGE_URL
    except NameError:
        rvi_logger.error('%s: RVI_SERVICE_EDGE_URL not defined. Check settings!', remote)

    rvi_server = None

    try:
        rvi_server = jsonrpclib.Server(rvi_service_url)
    except Exception as e:
        logger.error('%s: Cannot connect to RVI service edge: %s', vehicleVIN, e)  
    # print("In get user data")
    try:
        nodeID = node_identifier.rsplit("/", 1)[-1]
        dev, user = validate_device(nodeID)
    except Exception:
        rvi_logger.exception(SERVER_NAME + 'Received data did not pass validation')
        return {u'status': 0}

    # print("Validated nodeID")
    vehs = Vehicle.objects.filter(account=user)
    if not vehs:
        # print("No vehicles that you own")
        pass
    else:
        # print(vehs)
        # print("Starting vehicles for loop creating remotes")
        for v in vehs:
            try:
                rem = Remote.objects.get(rem_device=dev, rem_vehicle=v)
                # print(rem)
            except:
                # print(nodeID)
                # print(v.veh_vin)
                # print(dev)
                # print(v)
                rem = Remote.objects.create(
                    rem_name = nodeID + v.veh_vin,
                    rem_uuid = nodeID + v.veh_vin,
                    rem_device = dev,
                    rem_vehicle = v,
                    rem_validfrom = datetime.datetime.utcnow(),
                    rem_validto = datetime.datetime.utcnow() + datetime.timedelta(days=365),
                    rem_lock = True,
                    rem_engine = True,
                    rem_trunk = True,
                    rem_horn = True,
                    rem_lights = True,
                    rem_windows = True,
                    rem_hazard = True
                )
                rem.save()
                # print("Saving remote")

    vehiclelist = []
    # Grab all remotes now
    rems = Remote.objects.filter(rem_device=dev)
    for r in rems:
        user_type = "guest"
        if dev.dev_owner == r.rem_vehicle.account.username:
            user_type = "owner"

        vehiclelist.append(
            {  
                "vehicle_url" : url_vehicle,
                "vehicle_port" : port_vehicle,
                "vehicle_id" : r.rem_vehicle.veh_vin,
                "display_name" : r.rem_vehicle.veh_name,
                "valid_from" : unicode(r.rem_validfrom).replace(' ', 'T').replace('+00:00', '')+'.000Z',
                #datetime.datetime.utcnow(),
                "valid_to" : unicode(r.rem_validto).replace(' ', 'T').replace('+00:00', '')+'.000Z',
                #datetime.datetime.utcnow() + datetime.timedelta(days=10000),
                "user_type" : user_type,
                "authorized_services" : {
                                            u'lock': unicode(r.rem_lock),
                                            u'engine': unicode(r.rem_engine),
                                            u'trunk': unicode(r.rem_trunk),
                                            u'windows': unicode(r.rem_windows),
                                            u'lights': unicode(r.rem_lights),
                                            u'hazard': unicode(r.rem_hazard),
                                            u'horn': unicode(r.rem_horn)
                }
            }
        )

    guestlist = []
    devs = Device.objects.all()

    for d in devs:
        if d.account.username == dev.account.username:
            continue
        try:
            rems = Remote.objects.filter(rem_device=d)
        except Exception as e:
            print(e)
            rems = []

        vlist = []
        for r in rems:
            user_type = "guest"
            if d.dev_owner == r.rem_vehicle.account.username:
                user_type = "owner"

            vlist.append(
                {
                    "vehicle_url" : url_vehicle,
                    "vehicle_port" : port_vehicle,
                    "vehicle_id" : r.rem_vehicle.veh_vin,
                    "display_name" : r.rem_vehicle.veh_name,
                    "valid_from" : unicode(r.rem_validfrom).replace(' ', 'T').replace('+00:00', '')+'.000Z',
                    #datetime.datetime.utcnow(),
                    "valid_to" : unicode(r.rem_validto).replace(' ', 'T').replace('+00:00', '')+'.000Z',
                    #datetime.datetime.utcnow() + datetime.timedelta(days=10000),
                    "user_type" : user_type,
                    "authorized_services" : {
                                                u'lock': unicode(r.rem_lock),
                                                u'engine': unicode(r.rem_engine),
                                                u'trunk': unicode(r.rem_trunk),
                                                u'windows': unicode(r.rem_windows),
                                                u'lights': unicode(r.rem_lights),
                                                u'hazard': unicode(r.rem_hazard),
                                                u'horn': unicode(r.rem_horn)
                    }
                }
            )

        guestlist.append(
            {
                "username" : d.account.username,
                "first_name" : d.account.first_name,
                "last_name" : d.account.last_name,
                "vehicles" : vlist
            }
        )



    try:
        # print("guests: {}".format(guestlist))
        # print("vehicles: {}".format(vehiclelist))
        rvi_server.message(
            calling_service = "get_user_data",
            service_name = "genivi.org/android/{}/account_management/set_user_data".format(dev.dev_uuid),
            transaction_id = str(int(time.time())),
            timeout = int(time.time()) + 5000,
            # parameters = {"credentials":[encoded_jwt]}
            parameters = {
                "username":user.username, 
                "first_name":user.first_name,
                "last_name":user.last_name,
                "guests":guestlist,
                "vehicles":vehiclelist 
            }
        )
    except Exception as e:
        print("RVI MESSAGE FAILED")
        print(e)


# def set_user_data(node_identifier, public_key, username, first_name, last_name):
#     try:
#         nodeID = node_identifier.rsplit("/", 1)[-1]
#         dev, user = validate_device(nodeID)
#     except Exception:
#         rvi_logger.exception(SERVER_NAME + 'Received data did not pass validation')
#         status = "failure"

#     try:
#         if user.username == username:
#             user.first_name = first_name
#             user.last_name = last_name
#             user.save()
#             status = "success"

#         else:
#             status = "failure"

#     except:
#         status = "failure"

#     rvi_server.message(
#         calling_service = "set_user_data",
#         service_name = "genivi.org/android/{}/dm/set_user_data".format(dev.dev_uuid),
#         transaction_id = str(int(time.time())),
#         timeout = int(time.time()) + 5000,
#         # parameters = {"credentials":[encoded_jwt]}
#         parameters = {"status":status}
#     )

#     return {u'status': 0}




def get_remote(node_identifier, public_key):
    print("hello")

def create_remote(username, first_name, last_name, guests, vehicles):

    try:
        rvi_service_url = settings.RVI_SERVICE_EDGE_URL
    except NameError:
        rvi_logger.error('%s: RVI_SERVICE_EDGE_URL not defined. Check settings!', remote)

    rvi_server = None

    try:
        rvi_server = jsonrpclib.Server(rvi_service_url)
    except Exception as e:
        logger.error('%s: Cannot connect to RVI service edge: %s', vehicleVIN, e)  

    # print(username)
    # print(vehicles)

    devs = Device.objects.filter(dev_owner=username)

    # print(devs)

    for v in vehicles:
        # veh = vehicles[0]
        vehicleVIN = v["vehicle_id"] 
        authorizedServices = v["authorized_services"]
        validFrom = v["valid_from"]
        validTo = v["valid_to"]

        # print(v)
        # print(vehicleVIN)
        # print(authorizedServices)
        # print(validFrom)
        # print(validTo)

        try:
            remote = validate_create_remote(username, vehicleVIN, authorizedServices, validFrom, validTo)
        except Exception:
            rvi_logger.exception(SERVER_NAME + 'Received data did not pass validation')
            return {u'status': 0}

        t1 = threading.Thread(target=thread_create_remote, args=(remote,))
        t1.start()

        # Put for loop for everything below this
        for d in devs:
            print("Checking authorized Services")
            right_to_invoke = ["genivi.org/+/+/credential_management/", "genivi.org/node/+/account_management/"]
            for k, v, in authorizedServices.items():
                # print(k, v)
                if k == "lock" and v:
                    right_to_invoke.append("genivi.org/node/{}/control/lock".format(vehicleVIN))
                    right_to_invoke.append("genivi.org/node/{}/control/unlock".format(vehicleVIN))
                elif k == "engine" and v:
                    right_to_invoke.append("genivi.org/node/{}/control/engine".format(vehicleVIN))
                elif k == "trunk" and v:
                    right_to_invoke.append("genivi.org/node/{}/control/trunk".format(vehicleVIN))
                elif k == "windows" and v:
                    right_to_invoke.append("genivi.org/node/{}/control/windows".format(vehicleVIN))
                elif k == "lights" and v:
                    right_to_invoke.append("genivi.org/node/{}/control/lights".format(vehicleVIN))
                elif k == "hazard" and v:
                    right_to_invoke.append("genivi.org/node/{}/control/hazard".format(vehicleVIN))
                elif k == "horn" and v:
                    right_to_invoke.append("genivi.org/node/{}/control/horn".format(vehicleVIN))

            # print("In thread lookup creds")
            str_signed_client = d.dev_signed_client
            stripped_client = str_signed_client.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "").replace("\n", "").replace("\r", "")

            jwt_chain = []

            # print(parser.parse(str(validFrom).replace('T', ' ').replace('0Z',' +0000')))

            cred = {
                "iss" : "GENIVI",
                "id" : "temp",
                # "right_to_receive" : "genivi.org/android/",
                # "right_to_invoke" : "genivi.org/+/+/dm/",
                "right_to_receive" : ["genivi.org/android/" + d.dev_uuid +"/"],
                "right_to_invoke" : right_to_invoke,
                "device_cert" : stripped_client,
                "validity" : {
                    "start" : int(time.mktime((parser.parse(str(validFrom).replace('T', ' ').replace('0Z',' +0000'))).timetuple())),
                    "stop" : int(time.mktime((parser.parse(str(validTo).replace('T', ' ').replace('0Z',' +0000'))).timetuple()))
                }
            }   

            # print(cred)

            jwt_chain.append(jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256"))

            try:
                rvi_server.message(
                    calling_service = "authorize_services",
                    service_name = "genivi.org/android/{}/credential_management/update_credentials".format(d.dev_uuid),
                    transaction_id = str(int(time.time())),
                    timeout = int(time.time()) + 5000,
                    # parameters = {"credentials":[encoded_jwt]}
                    parameters = {"credentials":jwt_chain}
                )

            except Exception as e:
                logger.error('%s: Cannot connect to RVI service edge: %s', remote, e)
                return False

            # get_user_data(d.dev_uuid)

            #CREATE REMOTE OBJECT IN DATABASE

            # t1.join()

    alldevices = Device.objects.all()
    for d in alldevices:
        print(d.dev_uuid)
        t1 = threading.Thread(target=get_user_data, args=(d.dev_uuid,))
        t1.start()

    return {u'status': 0}

def revoke_remote(username, first_name, last_name, guests, vehicles):
    try:
        rvi_service_url = settings.RVI_SERVICE_EDGE_URL
    except NameError:
        rvi_logger.error('%s: RVI_SERVICE_EDGE_URL not defined. Check settings!', remote)

    rvi_server = None

    try:
        rvi_server = jsonrpclib.Server(rvi_service_url)
    except Exception as e:
        logger.error('%s: Cannot connect to RVI service edge: %s', vehicleVIN, e)  

    # print(username)
    # print(vehicles)

    devs = Device.objects.filter(dev_owner=username)

    # print(devs)

    for v in vehicles:
        # veh = vehicles[0]
        vehicleVIN = v["vehicle_id"] 
        authorizedServices = v["authorized_services"]
        validFrom = v["valid_from"]
        validTo = v["valid_to"]

        # print(v)
        # print(vehicleVIN)
        # print(authorizedServices)
        # print(validFrom)
        # print(validTo)

        # Put for loop for everything below this
        for d in devs:
            try:
                Remote.objects.filter(rem_name = (d.dev_uuid+vehicleVIN)).delete()
                print("Deleting Remotes")
            except Exception:
                rvi_logger.exception(SERVER_NAME + 'Received data did not pass validation')
                return {u'status': 0}


            print("Checking authorized Services")
            right_to_invoke = ["genivi.org/+/+/credential_management/", "genivi.org/node/+/account_management/"]
            # print("In thread lookup creds")
            str_signed_client = d.dev_signed_client
            stripped_client = str_signed_client.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "").replace("\n", "").replace("\r", "")

            jwt_chain = []

            # print(parser.parse(str(validFrom).replace('T', ' ').replace('0Z',' +0000')))

            cred = {
                "iss" : "GENIVI",
                "id" : "temp",
                "right_to_receive" : ["genivi.org/android/" + d.dev_uuid +"/"],
                "right_to_invoke" : right_to_invoke,
                "device_cert" : stripped_client,
                "validity" : {
                    "start" : int(time.time()),
                    "stop" : int(time.time()) + 31536000
                }
            }   

            # print(cred)

            jwt_chain.append(jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256"))

            try:
                rvi_server.message(
                    calling_service = "authorize_services",
                    service_name = "genivi.org/android/{}/credential_management/update_credentials".format(d.dev_uuid),
                    transaction_id = str(int(time.time())),
                    timeout = int(time.time()) + 5000,
                    # parameters = {"credentials":[encoded_jwt]}
                    parameters = {"credentials":jwt_chain}
                )

            except Exception as e:
                logger.error('%s: Cannot connect to RVI service edge: %s', remote, e)
                return False

    alldevices = Device.objects.all()
    for d in alldevices:
        print(d.dev_uuid)
        t1 = threading.Thread(target=get_user_data, args=(d.dev_uuid,))
        t1.start()

    return {u'status': 0}


def request_creds(node_identifier, public_key):

    rvi_logger.info("Credential request by nodeID: {} | pubKeyID: {}".format(node_identifier, public_key))

    try:
        stripped_pub = public_key.replace("\n", "")
        cert_id = str(hashlib.sha1(stripped_pub.encode("utf-8")).hexdigest())

        nodeID = node_identifier.rsplit("/", 1)[-1]
        dev, user = validate_device(nodeID)
    except Exception:
        rvi_logger.exception(SERVER_NAME + 'Received data did not pass validation')
        return {u'status': 0}

    t1 = threading.Thread(target=thread_lookup_creds, args=(dev, user, ))
    t1.start()
    print("Found and validated device")

    return {u'status': 0}


# Support (thread) functions
def thread_create_remote(remote):
    if Remote.objects.filter(rem_name = remote.rem_name).exists():
        rvi_logger.warning(SERVER_NAME + 'Deleting existing remote, %s', remote.get_name())
        Remote.objects.filter(rem_name = remote.rem_name).delete()

    remote.save()

    rvi_logger.info(SERVER_NAME + 'Remote created')


    # result = send_remote(remote)
    # if result:
    #     rvi_logger.info('Successfully Sent Remote: %s', remote.get_name())
    # else:
    #     rvi_logger.error('Failed Sending Remote: %s', remote.get_name())


def thread_modify_remote(remote):
    remote.save(update_fields=[
        'rem_validfrom',
        'rem_validto',
        'rem_lock',
        'rem_engine',
        'rem_trunk',
        'rem_windows',
        'rem_lights',
        'rem_hazard',
        'rem_horn'
    ])
    rvi_logger.info(SERVER_NAME + 'Remote updated')

    result = send_remote(remote)

    if result:
        rvi_logger.info('Sending Remote: %s - successful', remote.get_name())
    else:
        rvi_logger.error('Sending Remote: %s - failed', remote.get_name())

    # Pseudo revoke. If all authorized services false, delete remote
    if remote.rem_lock == remote.rem_engine == False:
        rvi_logger.warning(SERVER_NAME + 'Deleting remote, %s', remote.get_name())
        Remote.objects.filter(rem_name = remote.rem_name).delete()


def thread_lookup_creds(dev, user):


    try:
        rvi_service_url = settings.RVI_SERVICE_EDGE_URL
    except NameError:
        rvi_logger.error('%s: RVI_SERVICE_EDGE_URL not defined. Check settings!', remote)

    rvi_server = None

    try:
        rvi_server = jsonrpclib.Server(rvi_service_url)
    except Exception as e:
        logger.error('%s: Cannot connect to RVI service edge: %s', vehicleVIN, e)  

    print("In thread lookup creds")
    str_signed_client = dev.dev_signed_client
    stripped_client = str_signed_client.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "").replace("\n", "").replace("\r", "")

    jwt_chain = []

    cred = {
        "iss" : "GENIVI",
        "id" : "temp",
        # "right_to_receive" : "genivi.org/android/",
        # "right_to_invoke" : "genivi.org/+/+/dm/",
        "right_to_receive" : ["genivi.org/android/" + dev.dev_uuid +"/"],
        "right_to_invoke" : ["genivi.org/+/+/credential_management/"],
        "device_cert" : stripped_client,
        "validity" : {
            "start" : int(time.time()),
            "stop" : int(time.time()) + 31536000
        }
    }   

    jwt_chain.append(jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256"))

    vehs = Vehicle.objects.filter(account=user)
    for v in vehs:
        cred["right_to_invoke"] = ["{}/node/{}/".format(v.veh_rvibasename, v.veh_vin)]
        jwt_chain.append(jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256"))

    cred["right_to_invoke"] = ["genivi.org/+/+/credential_management/", "genivi.org/node/+/account_management/"]

    for v in vehs:
        cred["right_to_invoke"].append("genivi.org/node/+/account_management/{}".format(v.veh_vin))
        cred["right_to_invoke"].append("{}/node/{}/".format(v.veh_rvibasename, v.veh_vin))

    # encoded_jwt = jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256")
    jwt_chain.append(jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256"))

    # rvi_server = None

    # try:
    #     rvi_server = jsonrpclib.Server(rvi_service_url)
    # except Exception as e:
    #     logger.error('%s: Cannot connect to RVI service edge: %s', vehicleVIN, e)
    #     return False    

    try:
        rvi_server.message(
            calling_service = "certificate_manager",
            service_name = "genivi.org/android/{}/credential_management/update_credentials".format(dev.dev_uuid),
            transaction_id = str(int(time.time())),
            timeout = int(time.time()) + 5000,
            # parameters = {"credentials":[encoded_jwt]}
            parameters = {"credentials":jwt_chain}
        )

    except Exception as e:
        logger.error('%s: Cannot connect to RVI service edge: %s', remote, e)
        return False

    print("Successfuly sent stuff")
    return True


# Validation functions
def validate_create_remote(username, vehicleVIN, authorizedServices, validFrom, validTo):
    try:
        device = Device.objects.get(dev_owner=username)
        vehicle = Vehicle.objects.get(veh_vin=vehicleVIN)
        json_authorizedServices = authorizedServices
        lock = json_authorizedServices[u'lock']
        start = json_authorizedServices[u'engine']
        trunk = json_authorizedServices[u'trunk']
        windows = json_authorizedServices[u'windows']
        lights = json_authorizedServices[u'lights']
        hazard = json_authorizedServices[u'hazard']
        horn = json_authorizedServices[u'horn']
        validFrom = parser.parse(str(validFrom).replace('T', ' ').replace('0Z',' +0000'))
        validTo = parser.parse(str(validTo).replace('T', ' ').replace('0Z',' +0000'))

    except Device.DoesNotExist:
        rvi_logger.error(SERVER_NAME + 'username does not exist: %s', username)
        raise
    except Vehicle.DoesNotExist:
        rvi_logger.error(SERVER_NAME + ' VIN does not exist: %s', vehicleVIN)
        raise
    except Exception as e:
        rvi_logger.error(SERVER_NAME + 'Generic Error: %s', e)
        raise

    return Remote(
        rem_name = str(device.dev_uuid) + str(vehicleVIN) ,
        rem_device = device,
        rem_vehicle = vehicle,
        rem_validfrom = validFrom,
        rem_validto = validTo,
        rem_lock = lock,
        rem_engine = start,
        rem_trunk = trunk,
        rem_windows = windows,
        rem_lights = lights,
        rem_hazard = hazard,
        rem_horn = horn,
        rem_uuid = str(uuid.uuid4())
    )


def validate_modify_remote(certid, authorizedServices, validFrom, validTo):
    try:
        remote = Remote.objects.get(rem_uuid=certid)
        json_authorizedServices = authorizedServices
        lock = json_authorizedServices['lock']
        start = json_authorizedServices['engine']
        trunk = json_authorizedServices['trunk']
        windows = json_authorizedServices['windows']
        lights = json_authorizedServices['lights']
        hazard = json_authorizedServices['hazard']
        horn = json_authorizedServices['horn']

        validFrom = parser.parse(
            str(validFrom).replace('T', ' ').replace('0Z',' +0000')
        )
        validTo = parser.parse(
            str(validTo).replace('T', ' ').replace('0Z',' +0000')
        )
    except Remote.DoesNotExist:
        rvi_logger.error(SERVER_NAME + 'remote does not exist: %s', certid)
        raise
    except Exception as e:
        rvi_logger.error(SERVER_NAME + 'Generic Error: %s', e)
        raise

    remote.rem_validfrom = validFrom
    remote.rem_validto = validTo
    remote.rem_lock = lock
    remote.rem_engine = start
    remote.rem_trunk = trunk
    remote.rem_windows = windows
    remote.rem_lights = lights
    remote.rem_hazard = hazard
    remote.rem_horn = horn

    return remote

# def validate_remote(devi, vehi):
#     print("In validate remote")
#     try:
#         print(devi, vehi)
#         rem = Remote.objects.get(rem_device=devi, rem_vehicle=vehi)
#     except Exception as e:
#         print("what the "+ e)
#         return False

#     return True

def validate_device(nodeID):
    try:
        dev = Device.objects.get(dev_uuid=nodeID)
        user = dev.account

    except Device.DoesNotExist:
        rvi_logger.error(SERVER_NAME + 'Device does not exist: %s', nodeID)
        raise
    except Exception as e:
        rvi_logger.error(SERVER_NAME + 'Generic Error: %s', e)
        raise

    return (dev, user)


# Support functions
def parse_true_or_false(service):
    if service == u'true':
        return True
    else:
        return False