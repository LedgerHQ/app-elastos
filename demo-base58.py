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
import binascii
import sys
import base58

dongle = getDongle(True)

#print ("STARTED privateKey ")
#privateKey = dongle.exchange(bytes(bytearray.fromhex("80050000FF"+ bipp44_path)))
#actualPrivateKey = privateKey.hex().upper()
#expectPrivateKey = "55BCF45FFD718D8939FB798AAD5B5C8C55D3F08E42507D0D8479F50AB648639E"
#print ("ACTUAL privateKey " + actualPrivateKey)
#print ("EXPECT privateKey " + expectPrivateKey)
#print ("MATCH? privateKey " + str(actualPrivateKey == expectPrivateKey))

print("STARTED base58[1]")
# buggy for 2560-2569, 5120-5130, 7680-7690
# for value in range(2559, 2570):
for value in range(0, 70000):
    print("STARTED base58[1] " + str(value))
    valueHex = format(value, '06X')
    valueStr = base58.b58encode(binascii.unhexlify(valueHex)).decode('utf-8')
    print("INTERIM base58[1] valueHex " + valueHex)
    print("INTERIM base58[1] valueStr " + valueStr)
    inputbase58 = bytes(bytearray.fromhex(
        "80108000"
        # length
        + "04"
        # data
        + valueHex
    ))
    print("INTERIM base58[1] " + inputbase58.hex().upper())
    outputbase58 = dongle.exchange(inputbase58)
    actualbase58 = outputbase58[0x03:0x13].decode("utf-8")
    expectbase58 = valueStr
    print("ACTUAL base58[1] " + actualbase58)
    print("EXPECT base58[1] " + expectbase58)

    match = "yes" if (actualbase58 == expectbase58) else "no"
    print("MATCH? base58[1] " + match)

    if (match == "no"):
        raise ValueError('expected %s actual %s' %
                         (expectbase58, actualbase58))
print("SUCCESS base58[1]")

# sys.exit(1)
