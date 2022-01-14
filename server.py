# -*- coding: utf-8 -*-
"""
Created on Thu Dec  2 20:45:13 2021

@author: Arman Gupta
"""
import time
import socket
import pickle
import hmac
import hashlib
import os
import binascii
from x25519 import base_point_mult,multscalar 

s = socket.socket()
print("socket created")

s.bind(('localhost' , 9008)) #port number can be b/w 0 to 2^16-1

#listen to atmost 3 clients
s.listen(3)

print("waiting for the connection")

SECRET_KEY = b"YOU CAN'T GUESS THIS KEY"
#server is busy wiating
while True:
    #client socket(c) and address
    c , adr = s.accept()
    print("\nClient Connected with adress :", adr)
    #starting time
    start = time.time()
    #Receiving data containing public key and hash of the key from client
    C_public_key_exchange = c.recv(1024)
    deserialized_data = pickle.loads(C_public_key_exchange)
    CLIENT_PUB = deserialized_data['key']
    CLIENT_KEY_DIGEST = hmac.new(SECRET_KEY,binascii.hexlify(CLIENT_PUB.encode()),hashlib.sha256).hexdigest()
    
    #Authenticating the client
    if(CLIENT_KEY_DIGEST == deserialized_data['hash']):
        print("\nClient is verfied at server end\n")
        print("\nClient public:\t",binascii.hexlify(CLIENT_PUB.encode()))
        #server private key
        b = os.urandom(32)
        #server public key
        SERVER_PUB = base_point_mult(b) #bG
        
        print("\nServer private:\t",binascii.hexlify(b))
        print("\nServer public:\t",binascii.hexlify(SERVER_PUB.encode()))

        SERVER_KEY_DIGEST = hmac.new(SECRET_KEY, binascii.hexlify(SERVER_PUB.encode()), hashlib.sha256)

        #print(MSG_DIGEST.hexdigest())
        S_public_key_exchange = pickle.dumps({'hash' : SERVER_KEY_DIGEST.hexdigest() ,'key': SERVER_PUB})
        c.send(S_public_key_exchange)
        
        #Creating Server share
        y = os.urandom(32)
        SERVER_SHARE = multscalar(b,multscalar(y, CLIENT_PUB))
        #print("Server_Share in raw form :  ", SERVER_SHARE)
        print("\nServer Share:  ",binascii.hexlify(SERVER_SHARE.encode()))
        c.send(SERVER_SHARE.encode())
        
        CLIENT_SHARE = c.recv(1024).decode()
        print("\nClient share:\t",binascii.hexlify(CLIENT_SHARE.encode()))
        
        
        SHARED_SECRET_KEY = multscalar(y, CLIENT_SHARE)
        print("\nSHARED SECRET KEY :",binascii.hexlify(SHARED_SECRET_KEY.encode()))
        print("\nTotal Time in second = ", time.time() - start)
        c.close()
    else:
        print("CLient is not Verfied")
        c.close()
    
    