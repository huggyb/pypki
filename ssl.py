#!/usr/bin/python3.4

import getopt
import re
import sys
import os.path

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join

CA_CERT = 'cacert.crt'
CA_KEY = 'cakey.key'
PKI_DIR = 'key'

# Function cert_request
# Setup certificate attributes
def cert_request ():
    """
    Certificate request
    Setup certificates attributes
    return: cert object
    """
    cert = crypto.X509()
    cert.get_subject().C = input('Country: ')
    cert.get_subject().ST = input('State: ')
    cert.get_subject().L = input('Location: ')
    cert.get_subject().O = input('Organisation: ')
    cert.get_subject().OU = input('Organisational unit: ')
    cert.get_subject().CN = input('Common name: ')
    cert.set_serial_number(1)

    # valid period
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(cert.get_subject())
    return cert

def showhelp ():
    print("usage: ssl.py [OPTIONS]")
    print("\t-c --create\t-create clients certificates + key")
    print("\t--genca\t\t-create new ca")
    print("\t-h --help\t-print this menu")

# Parse command line arguments
if len(sys.argv) == 0:
    print ('usage : ' + usage)
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:],"ch:",["create","genca","help"])
except getopt.GetoptError:
    showhelp()
    sys.exit(2)
for opt, arg in opts:
    if opt in ( "-c", "--create" ):
        NEWREQ=1
    elif opt in ( "--genca" ):
        print( "Create new CA" )
        CA=1
    elif opt in ( "-h", "--help" ):
        showhelp()
        sys.exit(3)
    else:
        showhelp()
        sys.exit(5)


# main 
if CA == 1:
    if os.path.isfile( PKI_DIR + '/' + CA_CERT ) and os.path.isfile( PKI_DIR + '/' + CA_KEY ):
        print('There is an existing CA')
        
    # genkey
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    mycert = cert_request()
    mycert.set_pubkey(k)
    mycert.sign( k, 'sha256' )
    mycn = mycert.get_subject().CN
    
    open( PKI_DIR + '/' + CA_CERT, "wb" ).write( crypto.dump_certificate( crypto.FILETYPE_PEM, mycert ))
    open ( PKI_DIR + '/' + CA_KEY, "wb" ).write( crypto.dump_privatekey( crypto.FILETYPE_PEM, k ))


