####################
# General settings #
####################
#URL = "http://ndncert.named-data.net"
URL = "http://192.168.0.4:5000"

#################
# SMTP settings #
#################
#MAIL_FROM = "NDN Testbed Certificate Robot <noreply-ndncert@named-data.net>"
#MAIL_SERVER = "localhost"
MAIL_FROM = "NDN Testbed Certificate Robot <testname.zhehao@gmail.com>"
MAIL_SERVER = "smtp.gmail.com"

# MAIL_PORT = 25
# MAIL_USERNAME = ''
# MAIL_PASSWORD = ''
# MAIL_USE_SSL = True
MAIL_PORT = 465
MAIL_USERNAME = "testname.zhehao@gmail.com"
MAIL_PASSWORD = "test@2015"
MAIL_USE_SSL = True

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'

######################
# Namespace settings #
######################

NAME_PREFIX = '/zhehao'

############################
# Auto approve any request #
############################

AUTO_APPROVE = True
