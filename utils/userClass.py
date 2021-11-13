
# -*- coding: utf-8 -*-
"""
Created on Sat Oct 30 10:27:43 2021

@author: User
"""

from .utils_database import PMPDatabase
from .utils_crypt import encrypt_message, generate_key

securityNum = 23
keyDecoderEncoder = "dsadsafsa999923"

class user():
    def __init__(self,name,email,user_id,PMPDatabase):
        self.name = name
        self.email = email
        self.user_id = user_id
        self.PMPDatabase = PMPDatabase
        self.validVerify = None  # set in verifySecurityNumber
        self.keyEncoderDecoder = None # set in getEncoderDecoder
        self.listVault = None

    #get keys Encoder Decoder
    def getEncoderDecoder(self,sn):


        # keyEncoderDecoder =

        if self.validVerify:
            print('Succesful get Keys')
            self.keyEncoderDecoder = keyEncoderDecoder
            print("Key",self.keyEncoderDecoder)
            return self.keyEncoderDecoder

        else:
            print('Invalid Request')
            return None

    #verify Security Number
    def verifySecurityNumber(self,sn):
        securityNum = 23 # replace to query
        data = self.PMPDatabase.securityNumberCheckIs_v2(self.user_id,sn)

        if data['response']:
            print('Succesful Verify Number in User Class')
            self.validVerify = True
            self.keyEncoderDecoder = data['keyPass']
            return self.validVerify
        else:
            print('Invalid Number')
            self.validVerify = False
            return self.validVerify



    def getListVault(self,sites='all',decode=False):
        # decode: False -> only get tokens, True ->Decode Pas
        #
        uid = self.user_id
        ked = self.keyEncoderDecoder

        self.listVault = self.PMPDatabase.getListVaultFromDB(uid, ked,decode)
        return self.listVault

    def setItemVault(self,su,spn,sa,ruid,ralvl):
        # su: siteUser
        # sps: sitePassword like String
        # sa: siteAddress
        # ruid: relatedUser_ID
        # ralvl: relatedAccessLvl

        #keyEncoderDecoder
        key = self.keyEncoderDecoder
        spt = encrypt_message(spn,key)

        self.PMPDatabase.insertDataVault(su, spt, sa, ruid, ralvl)
        print('Password is Store now!')
        return True

    def newPassVault():
        return

    def updatePass():
        return

    def newSecurityNumber(self, sn):
        ea = self.email
        try:
            kpd = generate_key()
            self.PMPDatabase.insertSecurityNumber(ea ,sn ,kpd )
            print('Security Number is corretly set')
        except Exception as err:
            print('No se pudo configurar de manera correcta su Num de Seguridad')
            print(err)

    def updateSecurityNumber():
        return

    def deleletePass():
        return
