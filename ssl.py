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


def cert_request(list_attr):
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


def get_attr():
    """
    Ask user for certificates attributes
    Return list attr
    """
    attr = []
    for i in ('Country', 'State', 'Location', 'Organisation', 'Organizationnal Unit', 'Common Name'):
        a = input(i + ': ')
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
    args = parser.parse_args()

    check_and_create_dir(PKI_DIR)

    if args.generate_ca or args.default_ca:
        if exists_and_isfile(CA_CERT_FULLPATH) and exists_and_isfile(CA_KEY_FULLPATH):
            print('There is an existing CA')
            return
        if args.default_ca:
            default_attrs = ['PL', 'Poneyland', 'kichland', 'Poney Corp', 'info', 'ROOT-CA Poney CORP']
        else:
            default_attrs = get_attr()

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        my_cert = cert_request(default_attrs)
        my_cert.set_pubkey(k)
        my_cert.sign(k, 'sha256')

        with open(CA_CERT_FULLPATH, 'wb') as fd:
            fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, my_cert))
        with open(CA_KEY_FULLPATH, 'wb') as fd:
            fd.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

if __name__ == '__main__':
    main()
