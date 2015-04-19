#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import argparse

from OpenSSL import crypto

from utils import check_and_create_dir, exists_and_isfile

CA_CERT = 'cacert.crt'
CA_KEY = 'cakey.key'
PKI_DIR = 'key'

CA_CERT_FULLPATH = os.path.join(PKI_DIR, CA_CERT)
CA_KEY_FULLPATH = os.path.join(PKI_DIR, CA_KEY)


def cacert_req(list_attr):
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

    # valid period

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(cert.get_subject())
    return cert

def csr_req(list_attr):
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

    return cert

def get_attr():
    """
    Ask user for certificates attributes
    Return list attr
    """
    attr = []
    for i in ('Country', 'State', 'Location', 'Organisation', 'Organizationnal Unit', 'Common Name'):
        a = raw_input(i + ': ')
        attr += [a]
    return attr


def main():
    parser = argparse.ArgumentParser(description="Command line tool to manage a public key infrastructure.")
    parser.add_argument('-c', '--create', help="Creates client certificate and keys.", action='store_true',
                        default=False)
    parser.add_argument('-d', '--default-ca', help="Creates the root CA with default parameters.", action='store_true',
                        default=False)
    parser.add_argument('-g', '--generate-ca', help="Generates the root CA and ask for values.", action='store_true',
                        default=False)
    parser.add_argument('-l', '--list', help="List all certificates and keys that are present in the pki.",
                        action='store_true', default=False)
    parser.add_argument('-r', '--default-req', help="Creates client certificate and keys with default attributes.", 
                        action='store_true', default=False)
    args = parser.parse_args()

    check_and_create_dir(PKI_DIR)

    if args.generate_ca or args.default_ca:
        if exists_and_isfile(CA_CERT_FULLPATH) and exists_and_isfile(CA_KEY_FULLPATH):
            print('There is an existing CA')
            return
        if args.default_ca:
            default_attrs = ['PL', 'Poneyland', 'kichland', 'Poney Corp', 'ROOT-CA', 'ROOT-CA Poney CORP']
        else:
            default_attrs = get_attr()

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        my_cert = cacert_req(default_attrs)
        my_cert.set_pubkey(k)
        my_cert.sign(k, 'sha256')

        with open(CA_CERT_FULLPATH, 'wb') as fd:
            fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, my_cert))
        with open(CA_KEY_FULLPATH, 'wb') as fd:
            fd.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    elif args.create or args.default_req:
        if args.default_req:
            cli_attrs = ['PL', 'Poneyland', 'kichland', 'Poney Corp', 'info', 'poney_test']
        else:
            cli_attrs = get_attr()

        # load ROOT CA private key
        ca_key_fd = open(CA_KEY_FULLPATH, 'rb').read()
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_fd )
        ca_cert_fd = open(CA_CERT_FULLPATH, 'rb').read()
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_fd )
        # create csr 
        cli_pkey = crypto.PKey()
        cli_pkey.generate_key(crypto.TYPE_RSA, 2048)
        cli_csr = csr_req( cli_attrs )
        cli_csr.set_pubkey(cli_pkey)
        cli_csr.sign( cli_pkey, 'sha256')

        cli_cert = crypto.X509()
        cli_cert.set_issuer(ca_cert.get_subject())
        cli_cert.gmtime_adj_notBefore(0)
        cli_cert.gmtime_adj_notAfter(315360000)
        cli_cert.set_serial_number(cli_csr.get_serial_number())
        cli_cert.set_subject(cli_csr.get_subject())
        cli_cert.set_pubkey(cli_csr.get_pubkey())
        cli_cert.sign( ca_key, 'sha256')
        with open('key/client.crt', 'wb') as fd:
            fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cli_cert))
        with open('key/client.key', 'wb') as fd:
            fd.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cli_pkey))









if __name__ == '__main__':
    main()
