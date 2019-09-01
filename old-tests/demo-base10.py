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

dongle = getDongle(True)

#print ("STARTED privateKey ")
#privateKey = dongle.exchange(bytes(bytearray.fromhex("80050000FF"+ bipp44_path)))
#actualPrivateKey = privateKey.hex().upper()
#expectPrivateKey = "55BCF45FFD718D8939FB798AAD5B5C8C55D3F08E42507D0D8479F50AB648639E"
#print ("ACTUAL privateKey " + actualPrivateKey)
#print ("EXPECT privateKey " + expectPrivateKey)
#print ("MATCH? privateKey " + str(actualPrivateKey == expectPrivateKey))

print("STARTED base10[1]")
# buggy for 2560-2569, 5120-5130, 7680-7690
# for value in range(2559, 2570):
for value in range(0, 70000):
    print("STARTED base10[1] " + str(value))
    valueHex = format(value, '06X')
    valueStr = format(value, '016')
    print("INTERIM base10[1] valueHex " + valueHex)
    print("INTERIM base10[1] valueStr " + valueStr)
    inputBase10 = bytes(bytearray.fromhex(
        "80108000"
        # length
        + "03"
        # data
        + valueHex
    ))
    print("INTERIM base10[1] " + inputBase10.hex().upper())
    outputBase10 = dongle.exchange(inputBase10)
    actualBase10 = outputBase10[0x03:0x13].decode("utf-8")
    expectBase10 = valueStr
    print("ACTUAL base10[1] " + actualBase10)
    print("EXPECT base10[1] " + expectBase10)

    match = "yes" if (actualBase10 == expectBase10) else "no"
    print("MATCH? base10[1] " + match)

    if (match == "no"):
        raise ValueError('expected %s actual %s' %
                         (expectBase10, actualBase10))
print("SUCCESS base10[1]")

# sys.exit(1)

print("STARTED publicKey[1] ")
publicKey = dongle.exchange(
    bytes(bytearray.fromhex("80040000FF" + bipp44_path)))
actualPublicKey = publicKey.hex().upper()
expectPublicKey = "0AD1D5CB2DB69BFE31560ED1909135D6D5FA6A471D35FD9B1424C84CA68B9C40"
print("ACTUAL publicKey[1] " + actualPublicKey)
print("EXPECT publicKey[1] " + expectPublicKey)
print("MATCH? publicKey[1] " + str(actualPublicKey == expectPublicKey))

print("STARTED publicKey[2] ")
publicKey = dongle.exchange(
    bytes(bytearray.fromhex("80040000FF" + bipp44_path)))
actualPublicKey = publicKey.hex().upper()
expectPublicKey = "0AD1D5CB2DB69BFE31560ED1909135D6D5FA6A471D35FD9B1424C84CA68B9C40"
print("ACTUAL publicKey[2] " + actualPublicKey)
print("EXPECT publicKey[2] " + expectPublicKey)
print("MATCH? publicKey[2] " + str(actualPublicKey == expectPublicKey))
