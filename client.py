# -*- coding: utf-8 -*-
"""
Created on Thu Dec  2 20:55:58 2021

@author: Arman Gupta
"""
import time
import socket
import hmac
import hashlib
import pickle
import os
import binascii
from x25519 import base_point_mult,multscalar 


c = socket.socket()
c.connect(('localhost', 9008))
SECRET_KEY = b"YOU CAN'T GUESS THIS KEY"

#Generating the public key and private key using ECC X25519
#Reference : https://datatracker.ietf.org/doc/html/rfc7748
#start time
start = time.time()
#generate first public key needed to send to server
a = os.urandom(32)
CLIENT_PUB = base_point_mult(a) # aG

print("Client private:  ",binascii.hexlify(a))
print("\nClient public:  ",binascii.hexlify(CLIENT_PUB.encode()))

KEY_DIGEST = hmac.new(SECRET_KEY, binascii.hexlify(CLIENT_PUB.encode()), hashlib.sha256)
C_public_key_exchange = pickle.dumps({'hash' : KEY_DIGEST.hexdigest() ,'key': CLIENT_PUB})
c.send(C_public_key_exchange)

#Receiving Server public key
S_public_key_exchange = c.recv(1024)
deserialized_data = pickle.loads(S_public_key_exchange)
SERVER_PUB = deserialized_data['key']
SERVER_KEY_DIGEST = hmac.new(SECRET_KEY,binascii.hexlify(SERVER_PUB.encode()),hashlib.sha256).hexdigest()

#Authenticating the server
if(SERVER_KEY_DIGEST == deserialized_data['hash']):
    print("\nServer is authenticated at Client's end!")
    print("\nServer's public key :" ,binascii.hexlify(SERVER_PUB.encode()))
    
    x = os.urandom(32)
    CLIENT_SHARE = multscalar(a,multscalar(x, SERVER_PUB)) # axbG
    print("\nClient Share:  ",binascii.hexlify(CLIENT_SHARE.encode()))
    c.send(CLIENT_SHARE.encode())
    
    #Receving server share 
    SERVER_SHARE = c.recv(1024).decode() # yaG
    #print("\nServer Share in raw form:  ",SERVER_SHARE)
    print("\nServer Share:  ",binascii.hexlify(SERVER_SHARE.encode()))
    SHARED_SECRET_KEY = multscalar(x, SERVER_SHARE)
    print("\nSHARED SECRET KEY :",binascii.hexlify(SHARED_SECRET_KEY.encode()))
    print("\nTime taken in sec = ", time.time() - start)
else:
    print("\nServer authentication fails! Exiting....")


