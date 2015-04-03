#!/usr/bin/python3.4


import re

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join


CN = input('Common Name: ')
CERT_FILE = "%s.crt" % CN
KEY_FILE = "%s.key" % CN

# genkey
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)

# gencert
cert = crypto.X509()

#cert attr
cert.get_subject().C = input('Country: ')
cert.get_subject().ST = input('State: ')
cert.get_subject().L = input('Location: ')
cert.get_subject().O = input('Organisation: ')
cert.get_subject().OU = input('Organisational unit: ')
cert.get_subject().CN = CN

cert.set_serial_number(1)

# valid period
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(315360000)

cert.set_issuer(cert.get_subject())

cert.set_pubkey(k)
cert.sign( k, 'sha256' )

open( CERT_FILE, "wb" ).write( crypto.dump_certificate( crypto.FILETYPE_PEM, cert ))

open ( KEY_FILE, "wb" ).write( crypto.dump_privatekey( crypto.FILETYPE_PEM, k ))


