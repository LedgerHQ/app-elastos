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
textToSign_00_Hex = "020001000130024f7b54a22418633bc5cf2b4a9a445b64e89b0e54d193abb14387bba5c6e9e0060000000000004f7b54a22418633bc5cf2b4a9a445b64e89b0e54d193abb14387bba5c6e9e00601000100000002b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a340420f0000000000000000002100e7e7a87c8673c6a45b98f87bffb3be03944e55b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a3f46d4e0000000000000000002100e7e7a87c8673c6a45b98f87bffb3be03944e550000000001212000000000000000000000000000000000000000000000000000000000000069852321023845038e7a3f5f3a0d014f4327b6fa5744f5224aea240de802fcfe08740c349aac"
textToSign_00 = bytes(bytearray.fromhex(textToSign_00_Hex + bipp44_path))

textToSign_01_Hex = "02000100013001E49227311A5F781A619CF354E886F0ADA9724E250C2AC0F46FD458DCB14852F101000000000002B037DB964A231458D2D6FFD5EA18944C4F90E63D547C5D3B9874DF66A4EAD0A380969800000000000000000021BF8E2BB92E0604A0F3C1EA15E2D7E8729175795DB037DB964A231458D2D6FFD5EA18944C4F90E63D547C5D3B9874DF66A4EAD0A398465D05000000000000000021C624CAB1438F8FDDE9933222A8F1DD699C75F80200000000"
textToSign_01 = bytes(bytearray.fromhex(textToSign_01_Hex + bipp44_path))



textToSignArray = [textToSign_00, textToSign_01]

dongle = getDongle(True)

publicKey = dongle.exchange(bytes(bytearray.fromhex("8004000000" + bipp44_path)))
print("publicKey       [" + str(len(publicKey)) + "] " + publicKey.hex().upper())

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
