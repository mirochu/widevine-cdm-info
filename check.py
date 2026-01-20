# @mirochu - thx @moszkowski

import requests
import json
import base64
import os

import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

from pywidevine import Cdm, PSSH, Device

import argparse
from typing import Union
#Refactor, was a class
TRACK_TYPES = ["SD", "HD", "AUDIO"]

#Refactor, was a class
WIDEVINE_INTERNAL_STATUS = {
    127: "DRM_DEVICE_CERTIFICATE_REVOKED",
    175: "DRM_DEVICE_CERT_SERIAL_REVOKED",
    152: "INVALID_PSSH",
    106: "INVALID_LICENSE_CHALLENGE"
}

AES_KEY = bytes.fromhex("1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9")
AES_IV = bytes.fromhex("d58ce954203b7c9a9a9d467f59839249")

#This 2 values can be random, using the original ones from the leaked script
PROVIDER = "widevine_test"
CONTENT_ID = "ZmtqM2xqYVNkZmFsa3Izag=="

LICENSE_URL = "https://license.widevine.com/cenc/getlicense/widevine_test"

def buildRequest(challenge: Union[str, bytes]):
    """Build signed Widevine license request payload."""

    if isinstance(challenge, bytes):
        challenge = base64.b64encode(challenge).decode()

    payload = {
        "payload": challenge,
        "provider": PROVIDER,
        "content_id": CONTENT_ID,
        "content_key_specs": [{"track_type": t} for t in TRACK_TYPES]
    }

    payload = json.dumps(payload, separators=(",", ":"))

    hash = hashlib.sha1(payload.encode()).digest()
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)

    signature = cipher.encrypt(Padding.pad(hash, 16))
    signature = base64.b64encode(signature).decode()

    return {
        "request": base64.b64encode(payload.encode()).decode(),
        "signature": signature,
        "signer": PROVIDER,
    }

def getWidevineChallenge(certificate:Union[str, bytes], wvd:str)->bytes:
    
    device = Device.load(wvd)
    cdm = Cdm.from_device(device)
    pssh = PSSH("AAAAU3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADMSEAPfauf1SFfksTi+tMbKo18iFTI0N0NoYW5uZWwyMjVfY2F0Y2h1cCoCU0RI49yVmwY=") #Bitmovin PSSH, it can be a random PSSH

    session = cdm.open()

    cdm.set_service_certificate(session, certificate)

    return cdm.get_license_challenge(session, pssh, privacy_mode=True)

def main():

    parser = argparse.ArgumentParser(description="Widevine CDM Info")

    parser.add_argument("-c", "--cdm", help=("Widevine CDM (.wvd format)"), required=True)
    parser.add_argument("-x", "--proxy", help=("Optional proxy"))

    args = parser.parse_args()

    if not os.path.isfile(args.cdm):
        print("CDM not found!")
        exit(1)

    proxies = {"http": args.proxy, "https": args.proxy}

    #1st step, certificate retrival (needed for generating the challenge)

    certificateResponse = requests.post(LICENSE_URL, json=buildRequest(Cdm.service_certificate_challenge), proxies=proxies)
    if not certificateResponse.ok:
        print("Error getting certificate from apis!")
        exit(1)

    serviceCertificate = certificateResponse.json().get("license")

    #2nd step, challenge with random PSSH

    challenge = getWidevineChallenge(serviceCertificate, args.cdm)

    licenseResponse = requests.post(LICENSE_URL, json=buildRequest(challenge), proxies=proxies).json()

    print(json.dumps(licenseResponse, indent=4))

    if licenseResponse.get("status") == "ACCESS_DENIED":
        statusCode = licenseResponse.get("internal_status", 0)

        statusMessage = "License Error: " + (WIDEVINE_INTERNAL_STATUS[statusCode] + " " if WIDEVINE_INTERNAL_STATUS.get(statusCode) else "") + f"({statusCode})"

        print(f"\n\n{statusMessage}\n\n")


if __name__ == "__main__":
    main()
    
