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


dongle = getDongle(True)

# print("STARTED base58[FF]")
# valueHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
# # valueStr = base58.b58encode(binascii.unhexlify(valueHex)).decode('utf-8')
# # print("INTERIM base58[1] valueHex " + valueHex)
# # print("INTERIM base58[1] valueStr " + valueStr)
# inputbase58 = bytes(bytearray.fromhex(
#     "80588000"
#     # length
#     + "19"
#     # data
#     + valueHex
# ))
# print("INTERIM base58[1] " + inputbase58.hex().upper())
# outputbase58 = dongle.exchange(inputbase58)
# print("INTERIM base58[2] " + outputbase58.hex().upper())
# interimbase58 = outputbase58[0x03:0x26]
# print("INTERIM base58[3] " + interimbase58.hex().upper())
# actualbase58 = interimbase58.decode("utf-8")
# # expectbase58 = valueStr
# print("ACTUAL base58[1] " + actualbase58)

verificationScript = dongle.exchange(bytes(bytearray.fromhex("80050000FF" + bipp44_path)))
print("verif Script    [" + str(len(verificationScript)) + "] " + verificationScript.hex().upper())

publicKey = dongle.exchange(bytes(bytearray.fromhex("80040000FF" + bipp44_path)))
print("publicKey       [" + str(len(publicKey)) + "] " + publicKey.hex().upper())
