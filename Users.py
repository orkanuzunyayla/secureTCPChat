
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode
from socket import *

SALT_SIZE = 16

users={}
userFile = open('users2.txt', 'r') 
userLines = userFile.readlines()
for line in userLines:
	formattedUserLine = line.strip().split("\t")
	users[formattedUserLine[0]] = [formattedUserLine[1],formattedUserLine[2]]



class User(object):  #Variable = Attribute & func = method
	"""docstring for Users""" 


	def __init__(self, username, salt, passwordSaltHash):
		#super(User, self).__init__()
		self.username = username
		self.salt = salt
		self.passwordSaltHash = passwordSaltHash

	def userList():
		print(users)

	def checkUserExistance(self):

		userExistance = False
		
		if self.username in users.keys():
			if users[self.username][1] == self.passwordSaltHash:
				userExistance = True
			return userExistance
			
		else:
			return userExistance

	def server_program():
		# get the hostname
		host = 'localhost'
		port = 1235  # initiate port no above 1024

		serverSocket = socket(AF_INET,SOCK_STREAM)  # get instance
		# look closely. The bind() function takes tuple as argument
		serverSocket.bind((host, port))  # bind host address and port together
		serverSocket.listen(5)


		while True:
			# receive data stream. it won't accept data packet greater than 1024 bytes
			connection, address = serverSocket.accept()  # accept new connection
			print("Connection from: " + str(address),' username')
			data = connection.recv(1024).decode()
			if not data:
				# if data is not received break
				break
			print("username " + str(data))
			data = input(' -> ')
			connection.send(data.encode())  # send data to the client

		connection.close()  # close the connection



