#!/usr/bin/env python
# -*- coding: utf-8 -*-i

import ldap

LDAP_HOST = 'test'
LDAP_PORT = '389'
LDAP_URI = 'ldap://' + LDAP_HOST + ':' + LDAP_PORT

BIND_DN = ''
BIND_PW = '' 


ld = ldap.initialize(LDAP_URI)
tt = ld.bind( BIND_DN, BIND_PW )
ld_search = ld.search_s( 'dc=kich,dc=land', ldap.SCOPE_SUBTREE , )
for dn,entry in ld_search:
    for key,value in entry.viewitems():
        if key == 'userPassword':
            print(dn)
            print( key + ': ' +  str(value) )
#ld.search_s('ou=Testing,dc=stroeder,dc=de',ldap.SCOPE_SUBTREE,'(cn=fred*)',['cn','mail'])
#[('cn=Fred Feuerstein,ou=Testing,dc=stroeder,dc=de', {'cn': ['Fred
#Feuerstein']})]
#r =
#l.search_s('ou=Testing,dc=stroeder,dc=de',ldap.SCOPE_SUBTREE,'(objectClass=*)',['cn','mail'])
#for dn,entry in r:
#    print 'Processing',repr(dn)
#    handle_ldap_entry(entry)
#
#
