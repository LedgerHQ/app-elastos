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
textToSign_00_Hex = "02000100013001E49227311A5F781A619CF354E886F0ADA9724E250C2AC0F46FD458DCB14852F101000000000002B037DB964A231458D2D6FFD5EA18944C4F90E63D547C5D3B9874DF66A4EAD0A380969800000000000000000021BF8E2BB92E0604A0F3C1EA15E2D7E8729175795DB037DB964A231458D2D6FFD5EA18944C4F90E63D547C5D3B9874DF66A4EAD0A398465D05000000000000000021C624CAB1438F8FDDE9933222A8F1DD699C75F80200000000"
textToSign_00 = bytes(bytearray.fromhex(textToSign_00_Hex + bipp44_path))

textToSignArray = [textToSign_00]

dongle = getDongle(True)

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
