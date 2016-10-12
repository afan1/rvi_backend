from django.shortcuts import render

from django.http import HttpResponse

from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

from django.contrib.auth.models import User
from devices.models import Device

import json
import jwt
import time
import hashlib
import uuid

from OpenSSL import crypto
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import load_certificate_request
from OpenSSL.crypto import load_privatekey
from OpenSSL.crypto import load_publickey
from OpenSSL.crypto import dump_certificate
from OpenSSL.crypto import dump_certificate_request
from OpenSSL.crypto import dump_publickey
from OpenSSL.crypto import FILETYPE_PEM

from Crypto.PublicKey import RSA

from smtplib import SMTP
from email.mime.text import MIMEText

email_account = "pki@nginfotpdx.net"
PASSWORD = "NmxnvLWx2fhs9YXY"
SMTPserver = 'mail.nginfotpdx.net'
text_subtype = 'html'

root_file = open("privateKey.key", "r")
read_string = root_file.read()
root_key = load_privatekey(FILETYPE_PEM, read_string)
# signing_key = RSA.importKey(read_string)
root_file.close()

signing_file = open("rsaprivkey.key", "r")
signing_key = RSA.importKey(signing_file.read())
signing_file.close()

pub_file = open("pubkey.pem", "r")
pub_key = load_publickey(FILETYPE_PEM, pub_file.read())
pub_file.close()

cert_file = open("certificate.crt", "r")
raw_cert = cert_file.read()
cert_key = load_certificate(FILETYPE_PEM, raw_cert)
cert_file.close()

# Create your views here.
@csrf_exempt
@require_POST
def csr(request):
    try:
        print(request.body)
        data = request.body

        str_data = str(data.decode('utf-8'))
        # try:
        #     curs = db.cursor()
        # except:
        #     db = MySQLdb.connect(host="localhost", port=3306,user="pki", passwd="pki",db="pki")
        #     curs = db.cursor()

        cert = load_certificate_request(FILETYPE_PEM, str_data)
        client_pub_key = str(dump_publickey(FILETYPE_PEM, cert.get_pubkey()).decode("utf-8"))

        subject = cert.get_subject()

        components = dict((cert.get_subject()).get_components())
        print(components)

        node_uuid = str(components[b"CN"].decode("utf-8")).rsplit("/", 1)[-1]
        print(node_uuid)

        requester_email = str(components[b"emailAddress"].decode("utf-8"))

        try:
            user = User.objects.get(username=requester_email)
            print(user)
        except Exception as e:
            print(e)
            user = User.objects.create_user(requester_email, requester_email, "defaultpassword")
            user.save()
            print("Creating user: {}".format(requester_email))

        cert_id = str(hashlib.sha1(client_pub_key.encode("utf-8")).hexdigest())
        print("cert_id: " + cert_id)
        print("requester_email: " + requester_email)
        suffix = (requester_email.split('+', 1)[-1])
        # print(suffix)
        # print(suffix.split('@', 1)[0])
        usr_name = suffix.split('@', 1)[0]

        email_token = uuid.uuid4()
        print("email_token: ", email_token)

        if usr_name = "":
            usr_name = requester_email

        # Check if pubkey already exists
        try:
            device = Device.objects.get(dev_name=cert_id)
            print(device)
            device.dev_token = email_token
            device.save()
        except Exception as e:
            new_device = Device.objects.create(account=user, dev_name=cert_id, dev_owner=requester_email, dev_token=email_token, dev_cert_req=str_data, dev_uuid=node_uuid)
            new_device.save()

        # try:
        #     curs.execute(
        #         """INSERT INTO pki.csrs (email, date_requested, confirmation_token, token_date, cert_request, validated, cert_id) 
        #             VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        #         (requester_email, time.strftime('%Y-%m-%d %H:%M:%S'), email_token, 
        #         time.strftime('%Y-%m-%d %H:%M:%S'), str_data, 0, cert_id)
        #     )
        # except:
        #     curs.execute(
        #         """REPLACE INTO pki.csrs (email, date_requested, confirmation_token, token_date, cert_request, validated, cert_id) 
        #             VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        #         (requester_email, time.strftime('%Y-%m-%d %H:%M:%S'), email_token, 
        #         time.strftime('%Y-%m-%d %H:%M:%S'), str_data, 0, cert_id)
        #     )

        # db.commit()
        # curs.close()

        content="""
            <html>
                <head></head>
                <body>
                    <br>
                    <p> Please verify that you are {} </p>
                    <a href='unlock://www.nginfotpdx.net/token-verification?tokencode={}&certid={}'> Verify </a>
                    <br>
                </body>
            </html>
        """.format(usr_name.title(), email_token, cert_id)
        subject = "Sent from webserver"

        try:
            msg = MIMEText(content, text_subtype)
            msg['Subject']= subject
            msg['From'] = email_account # some SMTP servers will do this automatically, not all

            # print("Trying to connect to SMTP Server")
            conn = SMTP(SMTPserver, 587)
            conn.ehlo()
            conn.starttls()
            conn.ehlo()
            conn.set_debuglevel(False)
            conn.login(email_account, PASSWORD)
            try:
                conn.sendmail(email_account, [requester_email], msg.as_string())
                print("Sending mail")
            finally:
                conn.quit()

        except Exception as exc:
            print(exc) # give a error message


        return HttpResponse("INFO: CSR RECEIVED\n")

    except Exception as e:
        print("Not a valid pem CSR, {}".format(e))
        return HttpResponse("Not a valid pem CSR")

    return HttpResponse("What")


@csrf_exempt
@require_POST
def verify(request):

    data = request.body

    str_data = str(data.decode('utf-8'))

    try:
        decoded = jwt.decode(str_data, verify=False)
        sub = json.loads(decoded["sub"])

        # components = jwt.decode(str_data, '')
        print("token: " + sub["token"])
        print("certId: " + sub["certId"])

        try:
            device = Device.objects.get(dev_name=sub["certId"])
        except:
            print("No device found")
            return HttpResponse("No device with pubkey found")


        client_cert = load_certificate_request(FILETYPE_PEM, device.dev_cert_req)
        client_pub_key = dump_publickey(FILETYPE_PEM, client_cert.get_pubkey())
    except Exception as e:
        print(e)
        return HttpResponse("Verification Unsuccessful")

    try:
        verify = jwt.decode(str_data, client_pub_key, algorithm=["rsa256"])
        print(verify)
        verified_payload = json.loads(verify["sub"])
        returned_token = verified_payload["token"]
        if device.dev_token == returned_token:
            device.dev_validated = True
            device.save()

        else:
            print("Not valid token code")
            return HttpResponse("Token code not matched")

    except Exception as e:
        print(e)
        return HttpResponse("Verification Unsuccessful")

    cert = crypto.X509()
    cert.set_serial_number(int(time.time()*1000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)

    cert.set_issuer(cert_key.get_subject())
    cert.set_subject(client_cert.get_subject())
    cert.set_pubkey(client_cert.get_pubkey())

    cert.sign(root_key, "sha256")

    str_signed_client = str(dump_certificate(FILETYPE_PEM, cert).decode("utf-8"))

    device.dev_signed_client = str_signed_client
    device.save()

    reply = {}

    reply["signed_certificate"] = str_signed_client
    reply["server_certificate"] = raw_cert

    # stripped_client = str_signed_client.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "").replace("\n", "").replace("\r", "")
    stripped_client = str_signed_client.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "").replace("\n", "").replace("\r", "")

    cred = {
        "iss" : "GENIVI",
        "id" : "temp",
        # "right_to_receive" : "genivi.org/android/",
        # "right_to_invoke" : "genivi.org/+/+/dm/",
        "right_to_receive" : ["genivi.org/android/" + device.dev_uuid +"/"],
        "right_to_invoke" : ["genivi.org/+/+/credential_management/"],
        "device_cert" : stripped_client,
        "validity" : {
            "start" : int(time.time()),
            "stop" : int(time.time()) + 31536000
        }
    }

    # print(cred)

    encoded_jwt = jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256")

    reply["jwt"] = [encoded_jwt.decode("utf-8")]

    # print(reply)
    device.dev_root_reply = json.dumps(reply)
    device.save()


    return HttpResponse(json.dumps(reply))

@csrf_exempt
@require_POST
def csr_veh(request):
    data = request.body

    str_data = str(data.decode('utf-8'))

    client_cert = load_certificate_request(FILETYPE_PEM, str_data)

    cert = crypto.X509()
    cert.set_serial_number(int(time.time()*1000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)

    cert.set_issuer(cert_key.get_subject())
    cert.set_subject(client_cert.get_subject())
    cert.set_pubkey(client_cert.get_pubkey())

    cert.sign(root_key, "sha256")

    str_signed_client = dump_certificate(FILETYPE_PEM, cert).decode("utf-8")

    stripped_client = str_signed_client.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "").replace("\n", "").replace("\r", "")

    cred = {
        "iss" : "GENIVI",
        "id" : "temp",
        # "right_to_receive" : "genivi.org/android/",
        # "right_to_invoke" : "genivi.org/+/+/dm/",
        "right_to_receive" : ["genivi.org/node/genivi-amm-ftype/"],
        "right_to_invoke" : ["genivi.org/"],
        "device_cert" : stripped_client,
        "validity" : {
            "start" : int(time.time()),
            "stop" : int(time.time()) + 31536000
        }
    }
    encoded_jwt = jwt.encode(cred, signing_key.exportKey("PEM"), algorithm="RS256")

    reply = {}

    reply["signed_certificate"] = str_signed_client
    reply["server_certificate"] = raw_cert
    reply["jwt"] = [encoded_jwt.decode("utf-8")]
    
    print(reply)
    return(HttpResponse(json.dumps(reply)))

    # return HttpResponse(json.dumps(reply))
