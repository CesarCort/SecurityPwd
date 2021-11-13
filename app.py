import pandas
from utils import utils_database
from utils import utils_crypt


connect = utils_database.PMPDatabase()

# Step 1 | insert new user
# connect.insertNewUser("test", "LastName", "test4@test.com", "saltTest", "Epasas",1)

# Step 2 | insert new register from user
# print(connect.loginCheck('test4@test.com',"Epasas"))

# Step 3 | Insert Security Number
#key = utils_crypt.generate_key()
#connect.insertSecurityNumber('test4@test.com',25,key)

# Step 4 | Insert SecurityCheckIs
response = connect.securityNumberCheckIs( 'test4@test.com', 'Epasas', 25)
print(response)

# Last Step | End Close
connect.end()
