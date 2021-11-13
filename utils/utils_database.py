import sqlite3
import mysql.connector
from mysql.connector import Error
import hashlib
from .utils_crypt import generate_key, decrypt_message
import os
# Database credential

connection_config_dict = eval(os.getenv("SECURITY_PASS_DB"))

# This class is of MasterTable where app password(hashed) and email is stored in masterTable
class PMPDatabase():

    def __init__(self):
        try:
            self.connection = mysql.connector.connect(**connection_config_dict)

            if self.connection.is_connected():
                self.db_Info = self.connection.get_server_info()
                print("Connected to MySQL Server version ", self.db_Info)
                self.cursor = self.connection.cursor()

                # global connection timeout arguments
                global_connect_timeout = 'SET GLOBAL connect_timeout=180'
                global_wait_timeout = 'SET GLOBAL connect_timeout=180'
                global_interactive_timeout = 'SET GLOBAL connect_timeout=180'

                self.cursor.execute(global_connect_timeout)
                self.cursor.execute(global_wait_timeout)
                self.cursor.execute(global_interactive_timeout)
                self.cursor.execute("select database();")

                record = self.cursor.fetchone()
                print("You're connected to database: ", record)

        except Error as e:
            print("Error while connecting to MySQL", e)
        finally:
            # self.connection = mysql.connector.connect(**connection_config_dict)
            if self.connection.is_connected():
                self.cursor = self.connection.cursor()
                #self.cursor.close()
                #self.connection.close()
                #print("MySQL connection is closed")
	# This will create masterTable (which is done in passwordManagerApp.py file)

    def createTable(self):
        qCreate = """
        	CREATE TABLE IF NOT EXISTS masterTable (masterPass varchar(200), email varchar(100))
        """
        self.cursor.execute(qCreate)
        self.connect.commit()

    # Insert new user to platform
    def insertNewUser(self, fn, ln, ea, ps, pwd, aid, pn):
        # fn: FirstName
        # ln: LasttName
        # ea: EmailAddress
        # ps: PasswordSalt
        # pwd: Password
        # aid: Accounts_ID
        # pn: phoneNumber

        # Hash password
        bytesMP = bytes(pwd, 'utf-8')
        hashedMP = hashlib.sha256(bytesMP).hexdigest()

        qInsert = """
        	INSERT INTO user (FirstName, LastName, EmailAddress, PasswordSalt, PasswordHash, Accounts_ID, phoneNumber)
        	VALUES (%s, %s, %s, %s, %s, %s,%s)
        """

        self.cursor.execute(qInsert, (fn, ln, ea, ps, hashedMP, aid, pn))
        self.connection.commit()

        print("New User Created")

    def insertSecurityNumber(self,ea ,sn ,kpd ):
        # ea: EmailAddress
        # sn: SecurityNumber
        # kpd: keyPasswordDecryp

        sn = int(sn)

        qUserID = """
        	SELECT ID FROM user
            WHERE user.EmailAddress = '{}'
        """.format(ea)

        self.cursor.execute(qUserID)
        data = self.cursor.fetchall()
        user_ID = data[0][0] # Get user_id from EmailAddress

        qInsert = """
        	INSERT INTO decrypter (SecurityNumber,keyPassDecrypt, user_ID)
        	VALUES (%s, %s, %s)
        """

        self.cursor.execute(qInsert, (sn,kpd,user_ID))
        self.connection.commit()
        print("new security number insert successfully")

    def insertDataVault(self, su, spt, sa, ruid, ralvl):
        # su: siteUser
        # sp: sitePasswordToken
        # sa: siteAddress
        # ruid: relatedUser_ID
        # ralvl: relatedAccessLvl

        # Hash password Fernet Algorithm

        qInsert = """
        	INSERT INTO vault (siteUser, sitePassToken, siteAddress, relatedUser_ID, relatedAccessLvl )
        	VALUES (%s, %s, %s, %s, %s)
        """

        self.cursor.execute(qInsert, (su, spt, sa, ruid, ralvl))
        self.connection.commit()
        print("New Password is recorded")


	# This will hash the password and insert it along with email entered
    def insertIntoTable(self, mp, em):
        bytesMP = bytes(mp, 'utf-8')
        hashedMP = hashlib.sha256(bytesMP).hexdigest()

        qInsert = """
        	INSERT INTO masterTable (masterPass, email)
        	VALUES (?, ?)
        """
        self.cursor.execute(qInsert, (hashedMP, em))
        self.connection.commit()

	# This will update the existing password(hashed) instead of making a new row in database
	# This is called in resetPassFrame.py
    def updateIntoTable(self, mp):
        mail = self.getMail()
        bytesMP = bytes(mp, 'utf-8')
        hashedMP = hashlib.sha256(bytesMP).hexdigest()

        qUpdate = """
        	UPDATE masterTable SET masterPass = ? WHERE email = ?
        """
        self.cursor.execute(qUpdate, (hashedMP, mail))
        self.connect.commit()


        # This is used to check whether there is an existing user in passwordManagerApp.py
        # If user exists:
        # -> if True: setupFrame is raised
        # -> if False: loginFrame is raised
    def isEmpty(self):
        qCount = """
        	SELECT COUNT(*) FROM masterTable
        """
        self.cursor.execute(qCount)
        entries = self.cursor.fetchall()
        if (entries[0][0] == 0):
        	return True
        return

    def getUserid(self,ea):

        qSelect = """
        	SELECT * FROM user
            WHERE user.EmailAddress = '{}'
        """.format(ea)

        self.cursor.execute(qSelect)
        data = self.cursor.fetchall()

        self.user_ID = data[0][0]
        return self.user_ID

	# This is used in loginFrame.py to check the password with database
    def loginCheck(self, ea, pwd):

        bytesMP = bytes(pwd, 'utf-8')
        hashedMP = hashlib.sha256(bytesMP).hexdigest()

        qSelect = """
        	SELECT * FROM user
            WHERE user.EmailAddress = '{}'
        """.format(ea)

        self.cursor.execute(qSelect)
        data = self.cursor.fetchall()
        try:
            if len(data[0])>0:
                if hashedMP == data[0][5]:
                    print('Successful Login')
                    return [True, self.getUserid(ea)]

                else:
                    print('Failed Login dsd')
                    return False
            else: return False
        except:
            print('During login occur an Error')

    # True
    def securityNumberCheckIs_v1(self, ea, pwd,sn):

        bytesMP = bytes(pwd, 'utf-8')
        hashedMP = hashlib.sha256(bytesMP).hexdigest()

        qSelect = """
        	SELECT * FROM user
            WHERE user.EmailAddress = '{}'
        """.format(ea)
        self.cursor.execute(qSelect)
        data = self.cursor.fetchall()
        try:
            if len(data[0])>0:
                if hashedMP == data[0][5]:
                    print('Credential Validate')

                    qSelect = """
                    	SELECT * FROM decrypter
                        WHERE decrypter.user_ID = '{}'
                    """.format(data[0][0])

                    self.cursor.execute(qSelect)
                    data = self.cursor.fetchall()

                    if data[0][1] == sn:
                        print('securityNumber Validate')
                        return {'response':True,
                                'keyPass':data[0][2]}

                    else:
                        print('securityNumber Invalidate')
                        return {'response':False,
                                'keyPass':''}
                else:
                    print('Failed Login')
                    return False

            else: return False
        except:
            print('Failed Login')

    def securityNumberCheckIs_v2(self, uid, sn):
        # uid: user_ID
        #sn : SecurityNumber

        qSelect = """
        	SELECT * FROM decrypter
            WHERE decrypter.user_ID = '{}'
        """.format(uid)

        self.cursor.execute(qSelect)
        data = self.cursor.fetchall()
        try:
            if data[0][1] == sn:
                print('securityNumber Validate')

                return {'response':True,
                        'keyPass':data[0][2]}

            else:
                print('securityNumber Invalidate')
                return {'response':False,
                        'keyPass':''}

        except:
            print('Error While securityNumber Check')

    def getListVaultFromDB(self, uid, ked , decode, one=False):
        # uid: user_ID
        # ked: keyEncoderDecoder
        qSelect = """
        	SELECT * FROM vault  WHERE vault.relatedUser_ID = '{}'
        """.format(uid)

        self.cursor.execute(qSelect)
        data = self.cursor.fetchall()

        r = [dict((self.cursor.description[i][0], value) \
           for i, value in enumerate(row)) for row in data]
        jsonResponse = (r[0] if r else None) if one else r

        # Decode sitePassToken
        if decode:
            ked = ked.encode()
            for item in jsonResponse:
                spt = str(item.get('sitePassToken')).encode()
                item['sitePassToken'] = decrypt_message(spt,ked).decode()

        return jsonResponse


	# This is used in forgotPassFrame.py to check email entered with database
    def mailCheck(self, mail):
        qSelect = """
        	SELECT * FROM masterTable
        """
        self.cursor.execute(qSelect)
        data = self.cursor.fetchall()
        if mail == data[0][1]:
        	return True
        return False


	# Used in updateIntoTable() to get mail from databse
    def getMail(self):
        qSelect = """
        	SELECT * FROM masterTable
        """
        self.cursor.execute(qSelect)
        data = self.cursor.fetchall()
        # print(data[0][1])
        mail = data[0][1]
        return mail

    def end(self):
        self.cursor.close()
        self.connection.close()
        print("MySQL connection is closed")
