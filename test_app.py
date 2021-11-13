# -*- co/ding: utf-8 -*-
"""
Created on Sat Oct 30 13:55:06 2021

@author: User
"""

from utils.userClass import user
from utils.utils_database import PMPDatabase
from utils.utils_crypt import generate_key

# Conexion a BD
connection_db = PMPDatabase()
#%%
# Create/register new user
firstName = 'Cesar'
lastName = 'Cortez'
email = 'testing@gmail.com'
phoneNumber = '933428720'
pwd = 'contraseña'
#
aid = 1
ps = 'test'

connection_db.insertNewUser(firstName, lastName, email, ps, pwd, aid, phoneNumber)

#%% Set SecurityNumber

kpd = generate_key()
connection_db.insertSecurityNumber(email ,40 , kpd )

#%% Check Login like user

# email = 'test4@test.com'
# pwd = 'Epasas'

email = 'testing@gmail.com'
pwd = 'contraseña'
login_ = connection_db.loginCheck(email, pwd)

#%% If Logincheck is True then create a userObject

if login_[0]:
    userId = login_[1]
    # create a userObject
    user_ = user('cesar','test@test.com',userId,connection_db)

#%% VerifySecurityNumber

user_.verifySecurityNumber(40)

#%% Store password is SecurityNumber is Valid

if user_.validVerify:
    print('I can manage account')
    su = 'http://gmail.com'
    spn = 'trelotrelo'
    sa = 'test1@gmail.com'
    ruid = user_.user_id
    ralvl = 1
    
    user_.setItemVault(su, spn, sa, ruid, ralvl)

#%% see all PasswordStore

if user_.validVerify:
    listvault = user_.getListVault(decode=True)
    print('See all Password Store')

#%% Testing Zone
