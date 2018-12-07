#!/usr/bin/env python
# *******************************************************************************
# *   Ledger Blue
# *   (c) 2016 Ledger
# *
# *  Licensed under the Apache License, Version 2.0 (the "License");
# *  you may not use this file except in compliance with the License.
# *  You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# *  Unless required by applicable law or agreed to in writing, software
# *  distributed under the License is distributed on an "AS IS" BASIS,
# *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# *  See the License for the specific language governing permissions and
# *  limitations under the License.
# ********************************************************************************
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException

bipp44_path = (
    "8000002C"
    + "80000901"
    + "80000000"
    + "00000000"
    + "00000000")


# sending 1 ELA
textToSign_00_Hex = ""
textToSign_00 = bytes(bytearray.fromhex(textToSign_00_Hex + bipp44_path))

textToSignArray = [textToSign_00]

dongle = getDongle(True)
publicKey = dongle.exchange(bytes(bytearray.fromhex("80040000FF" + bipp44_path)))
print("publicKey       [" + str(len(publicKey)) + "] " + publicKey.hex().upper())

signedPublicKey = dongle.exchange(bytes(bytearray.fromhex("80080000FF" + bipp44_path)))
print("signedPublicKey [" + str(len(signedPublicKey)) + "] " + signedPublicKey.hex().upper())

signature = signedPublicKey[67:]
print("signature [" + str(len(signature)) + "] " + signature.hex().upper())

for textToSign in textToSignArray:
    try:
        offset = 0
        while offset != len(textToSign):
            if (len(textToSign) - offset) > 255:
                chunk = textToSign[offset: offset + 255]
            else:
                chunk = textToSign[offset:]
            if (offset + len(chunk)) == len(textToSign):
                p1 = 0x80
            else:
                p1 = 0x00
            apdu = bytes(bytearray.fromhex("8002")) + p1.to_bytes(1, byteorder='big') + 0x00.to_bytes(1, byteorder='big') + len(chunk).to_bytes(1, byteorder='big') + bytes(chunk)
            signature = dongle.exchange(apdu)
            offset += len(chunk)
        print("signature " + signature.hex().upper())
    except CommException as comm:
        if comm.sw == 0x6985:
            print("Aborted by user")
        else:
            print("Invalid status " + hex(comm.sw))
