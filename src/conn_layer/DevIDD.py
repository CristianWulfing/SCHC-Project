
# **************************************************************************
#   SCHC PROJECT
# **************************************************************************
#   AUTHOR: CRISTIAN AUGUSTO WüLFING
#   EMAIL: cris_wulfing@hotmail.com
#   CITY: Santa Maria - Rio Grande do Sul - Brasil
#   COMPANY: Fox IoT
# **************************************************************************
#   Copyright(c) 2023 Fox IoT.
# **************************************************************************

from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import binascii

# # Dev 01
# DevEUI  = 70B3D57ED0055D4F
# AppSKey = changeAppSKey

# # Dev 02
# DevEUI  = 70B3D57ED0058962
# AppSKey = changeAppSKey

class DevIDD:

    def __init__(self, DevEUI, AppSKey, IPv6DevPrefix):

        self.DevEUI         = DevEUI
        self.AppSKey        = AppSKey
        self.IPv6DevPrefix  = IPv6DevPrefix

        msg     = binascii.unhexlify(DevEUI)
        secret  = binascii.unhexlify(AppSKey)
        cobj    = CMAC.new(secret, ciphermod=AES)
        cobj.update(msg)

        self.hex = cobj.hexdigest()[0:16]

    def get(self):

        return (self.IPv6DevPrefix + ":" + self.hex[0:4] + ":" + self.hex[4:8] + ":" + self.hex[8:12] + ":" + self.hex[12:16]).replace('0', '')
