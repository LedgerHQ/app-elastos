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

# privateKey = dongle.exchange(bytes(bytearray.fromhex("80060000FF" + bipp44_path)))
# print("private key    [" + str(len(privateKey)) + "] " + privateKey.hex().upper())

## from javascript is 21023845038E7A3F5F3A0D014F4327B6FA5744F5224AEA240DE802FCFE08740C349AAC
## from ledger dev is 21023845038E7A3F5F3A0D014F4327B6FA5744F5224AEA240DE802FCFE08740C349AAC
# verificationScript = dongle.exchange(bytes(bytearray.fromhex("80050000FF" + bipp44_path)))
# print("verif Script    [" + str(len(verificationScript)) + "] " + verificationScript.hex().upper())


## from javascript is 043845038e7a3f5f3a0d014f4327b6fa5744f5224aea240de802fcfe08740c349acd97d041ead676d7443769d014055ea361ff09077e508e6f2780d9a4fd57757a
## from ledger dev is 043845038E7A3F5F3A0D014F4327B6FA5744F5224AEA240DE802FCFE08740C349ACD97D041EAD676D7443769D014055EA361FF09077E508E6F2780D9A4FD57757A
publicKey = dongle.exchange(bytes(bytearray.fromhex("8004000000" + bipp44_path)))
print("publicKey       [" + str(len(publicKey)) + "] " + publicKey.hex().upper())

## from javascript is 023845038E7A3F5F3A0D014F4327B6FA5744F5224AEA240DE802FCFE08740C349A
## from ledger dev is 023845038E7A3F5F3A0D014F4327B6FA5744F5224AEA240DE802FCFE08740C349A
# encodedPublicKey = dongle.exchange(bytes(bytearray.fromhex("80070000FF" + bipp44_path)))
# print("encodedPublicKey[" + str(len(encodedPublicKey)) + "] " + encodedPublicKey.hex().upper())

## from javascript is 2100E7E7A87C8673C6A45B98F87BFFB3BE03944E55
## from ledger dev is 2100E7E7A87C8673C6A45B98F87BFFB3BE03944E55
# scripthash = dongle.exchange(bytes(bytearray.fromhex("80090000FF" + bipp44_path)))
# print("scripthash      [" + str(len(scripthash)) + "] " + scripthash.hex().upper())

## from javascript is 2100E7E7A87C8673C6A45B98F87BFFB3BE03944E5504D98369
## from ledger dev is 2100E7E7A87C8673C6A45B98F87BFFB3BE03944E5504D98369
# address = dongle.exchange(bytes(bytearray.fromhex("80110000FF" + bipp44_path)))
# print("address         [" + str(len(address)) + "] " + address.hex().upper())

# outputbase58 = dongle.exchange(bytes(bytearray.fromhex(        "80588000"
#         # length
#         + "19"
#         # data
#         + '2100E7E7A87C8673C6A45B98F87BFFB3BE03944E5504D98369')))
# print("INTERIM address58[2] " + outputbase58.hex().upper())
# interimbase58 = outputbase58[0x03:0x26]
# print("INTERIM address58[3] " + interimbase58.hex().upper())
# actualbase58 = interimbase58.decode("utf-8")
# # expectbase58 = valueStr
# print("ACTUAL address58[1] " + actualbase58)
