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

# function cert_request
# fetup certificate attributes
def cert_request (list_attr):
    """
    Certificate request
    Setup certificates attributes
    return: cert object
    """

    cert = crypto.X509()
    cert.get_subject().C = list_attr[0]
    cert.get_subject().ST = list_attr[1]
    cert.get_subject().L = list_attr[2]
    cert.get_subject().O = list_attr[3]
    cert.get_subject().OU = list_attr[4]
    cert.get_subject().CN = list_attr[5]
    cert.set_serial_number(1)

    # valid period
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter( 315360000 )
    cert.set_issuer(cert.get_subject())
    return cert

# function get_attr
# ask user for certificates attributes
def get_attr ():
    """
    Ask user for certificates attributes
    Return list attr
    """
    attr = []
    for i in  ( 'Country',  'State', 'Location', 'Organisation',
            'Organizationnal Unit', 'Common Name' ):
        a = input( i + ': ' )
        attr += [ a ]
    
    return attr


# function showhelp
# print help
def showhelp ():
    """
    Print Help
    """
    print( 'usage: ssl.py [OPTIONS]' )
    print( "\t-c --create\t-create clients certificates + key" )
    print( "\t--defaultCA\t-create ROOT-CA with default param" )
    print( "\t--genca\t\t-create new ca" )
    print( "\t-h --help\t-print this menu" )



CA = 0
DEFCA = 0
NEWREQ = 0
# parse command line arguments
if len(sys.argv) == 0:
    print ( 'usage : ' + usage )
    sys.exit(1)

try:
    opts, args = getopt.getopt( sys.argv[1:], 'ch:', [ 'create', 'defaultCA',
            'genca', 'help' ])
except getopt.GetoptError:
    showhelp()
    sys.exit(2)
for opt, arg in opts:
    if opt in ( '-c', '--create' ):
        NEWREQ = 1
    if opt in ( '--defaultCA' ):
        print( 'create default ROOT-CA' )
        DEFCA = 1
        CA = 1
    elif opt in ( '--genca' ):
        CA = 1
    elif opt in ( '-h', '--help' ):
        showhelp()
        sys.exit(3)
    else:
        showhelp()
        sys.exit(5)


# main
if CA == 1:
    if os.path.isfile( PKI_DIR + '/' + CA_CERT ) and os.path.isfile( 
            PKI_DIR + '/' + CA_KEY ):
        print('There is an existing CA')
        
    print( 'Create new CA' )

    # get certificate attribues
if DEFCA == 1:
    my_attr = [ 'PL', 'Poneyland', 'kichland', 'Poney Corp', 'info',
            'ROOT-CA Poney CORP' ]
else:
    my_attr = ( get_attr() )
    
# genkey
k = crypto.PKey()
k.generate_key( crypto.TYPE_RSA, 2048 )


my_cert = cert_request( my_attr )
my_cert.set_pubkey(k)
my_cert.sign( k, 'sha256' )
my_cn = my_cert.get_subject().CN

open( PKI_DIR + '/' + CA_CERT, 'wb' ).write( crypto.dump_certificate(
    crypto.FILETYPE_PEM, my_cert ))
open ( PKI_DIR + '/' + CA_KEY, 'wb' ).write( crypto.dump_privatekey(
    crypto.FILETYPE_PEM, k ))
