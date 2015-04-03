#!/usr/bin/python3.4


import re

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join

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

PKI_DIR='key'



# genkey
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)

mycert = cert_request()

mycert.set_pubkey(k)
mycert.sign( k, 'sha256' )

mycn = mycert.get_subject().CN

print(mycn)

open( PKI_DIR + "/" + mycn + ".crt", "wb" ).write( crypto.dump_certificate( crypto.FILETYPE_PEM, mycert ))

open ( PKI_DIR + "/" + mycn + ".key", "wb" ).write( crypto.dump_privatekey( crypto.FILETYPE_PEM, k ))

# Function cert_request
# Setup certificate attributes




