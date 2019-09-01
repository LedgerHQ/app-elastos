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


# voting
textToSign_00_Hex = "090200010005117061845802D63203589E914DA39CBE4629FA3AA2AFA37B702055193AD6B5C1A93F62929DF9000000000000C337358A52F38BCA8467005B9A40E23C188D4135613AE2CC72FC40BF9F3C474D2B010000000002B037DB964A231458D2D6FFD5EA18944C4F90E63D547C5D3B9874DF66A4EAD0A3004A2E18150000000000000021BA4167455967473D8A91718926A356271B4479090100010003210205A250B3A96CCC776604FAFB84B0F8623FDFDA6EC8F42C9154AA727BD95EDFE22103D55285F06683C9E5C6B5892A688AFFD046940C7161571611EA3A98330F72459F2102512BF24FE87A7EB6D831F80A243721E4DA13735A4F1E5F2CC717B20F1974645CB037DB964A231458D2D6FFD5EA18944C4F90E63D547C5D3B9874DF66A4EAD0A3914300000000000000000000214B511222FB2D19C265F96FDFAF336790C54B548F00000000000141408866121D06827485C71DDE015022700389B9D3AAC802EB8E4B90AD0BE1A74F3243D4CCFEB1BE826FBDDD04844D2F9B3225CC170975CFD13109CC683F2AA0FB53232103B5EDAD7BB3376345DA6B374FB2F52026F66D3986AE63B257EEF2E6A1FB6727CEAC"
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
