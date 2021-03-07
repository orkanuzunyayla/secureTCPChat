
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from tkinter import *
from queue import *
from time import *
import threading
import sys
from socket import *
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode
import Users as u

def handle_client(conn):
	global server , clients , addresses
	while True:

		received_message = conn.recv(2560)
		username = clients[conn]

		if received_message != bytes("{quit}", "utf8"):
			decrypted_message = RSAdecryption(received_message)
			broadcast(decrypted_message, username+": ")
		else:
			try:
				conn.send(bytes("{quit}", "utf8"))
			except:
				pass
			if conn in clients: del clients[conn]
			if conn in addresses: del addresses[conn]
			if conn in pubKeys: del pubKeys[conn]
			broadcast(bytes("--%s has left the chat.--" %username, "utf8"))
			break

def broadcast(msg, prefix=""):
	global clients, addresses,pubKeys
	writeToBox(prefix,msg)
	if msg == bytes("{ServerShutdown}", "utf8"):
		try:
			for sock in clients:
				sock.send(bytes(prefix, "utf8")+msg)
		except:
			pass
	if 'has joined the chat--' not in msg.decode('utf8') and 'has left the chat.--' not in msg.decode('utf8'):
		try:
			print(clients)
			for sock in clients:
				clientPubKey = pubKeys[sock]
				send_message = RSAencrypt(bytes(prefix, "utf8")+msg,clientPubKey)
				print(send_message)
				sock.send(send_message)
		except Exception as e:
			print(e)
	else:
		try:
			for sock in clients:
				sock.send(bytes(prefix, "utf8")+msg)
		except Exception as e:
			print(e)



def create_active_connection (portno):
	global server , clients , addresses,myPubKey
	host = gethostname()
	port = portno
	server = socket(AF_INET,SOCK_STREAM)
	server.bind((host,port))
	server.listen()
	print(host)
	m = " Server is ready..."
	print(m)
	initPublicPrivateKeys()
	msgBox2.insert(END,m)
	msgBox2.see(END)
	textEntryPort1.config(state='disabled')
	serverRunning = True
	initThread = threading.Thread(target = initiate_connection)
	initThread.daemon=True
	initThread.start()

def initiate_connection():
	global server , clients , addresses, pubKeys
	while True:
		conn,addr = server.accept()
		print(" %s:%s has connected." %addr)
		addresses[conn] = addr
		try:
			usernameandpass = RSAdecryption(conn.recv(2560)).decode('utf8').split(':')
			username = usernameandpass[0]
			password = usernameandpass[1]
			clientPubKey= RSA.import_key(open('userPubCertificates/%sPublic.pem'%username, 'r').read())
			checkCredentialResult = checkCredentials(username,password)
			if checkCredentialResult:
				if username in clients.values():
					conn.send(bytes("{code2}", "utf8"))
					conn.close()
					if conn in clients: del clients[conn]
					if conn in addresses: del addresses[conn]
					if conn in pubKeys: del pubKeys[conn]
				else:
					conn.send(bytes("{code3}", "utf8"))
					clientThread= threading.Thread(target = handle_client, args = (conn,))
					clientThread.daemon=True
					clientThread.start()
					msg = "-- %s has joined the chat--" %username
					broadcast(bytes(msg, "utf8"))
					clients[conn] = username
					pubKeys[conn] = clientPubKey
			else:
				conn.send(bytes("{code1}", "utf8"))
				conn.close()
				if conn in addresses: del addresses[conn]

		except Exception as e:
			print(e)
			print("%s Connection Dropped." %username)


def terminateConnection():
	global server, clients , addresses , activeConnection
	broadcast(bytes("{ServerShutdown}", "utf8"))
	sleep(1)
	for conn in addresses:
		if conn in addresses:
			try:
				if conn in clients:
					print('Connection Closing for', clients[conn])
				sleep(1)
				conn.close()
				if conn in clients: del clients[conn]
			except:
				pass
	clients = {}
	addresses = {}
	activeConnection = False
	server.close()
	activeConnection = False
	change_gui_state(state=True)
	m = 'Connection terminated for port: %s' %textEntryPort1.get()
	print(m)
	msgBox2.insert(END,m)
	msgBox2.see(END)



def writeToBox(prefix,msg):
	if len(prefix)>1:
		m = (' '+prefix+':'+ msg.decode('utf-8'))
	else:
		m = (msg.decode('utf-8'))
	if m != "{ServerShutdown}":
		msgBox2.insert(END,m)
		msgBox2.see(END)

def receive_port_number(portnumber):
	global activeConnection
	change_gui_state(state=False)
	portNo = int(portnumber.get())
	if not activeConnection:
		try:
			create_active_connection(portNo)
		except Exception as e:
			print(e)
			change_gui_state(state=True)
			print('Connection Problem')

	else:
		print('There is already an active connection')

def checkConnectInputs(*arg):
	global enteredPortNo
	if len(enteredPortNo.get().strip())>3 and 1200<(int(enteredPortNo.get()))<65535:
		startButton.configure(state="normal")
	else:
		startButton.configure(state="disable")

def checkCredentials(username,password):

	alph = 'abcdefghijklmnopqrstuvwxyz'
	salt = ''
	for char in username:
		salt+= str(alph.index(char))
	hashh = SHA256.new((password+salt).encode("utf-8")).hexdigest()
	thisUser = u.User(username,salt,hashh)
	userExistance = thisUser.checkUserExistance()
	return userExistance

def window_close(event=None):
	global masterServer
	try: 
		terminateConnection()
	except Exception as e:
		print(e)
		masterServer.destroy()
	masterServer.destroy()

def change_gui_state(state):
	if state == False:
		textEntryPort1.config(state='disable')
		startButton['state']= DISABLED
		stopButton['state'] = NORMAL

	if state == True:
		textEntryPort1.config(state='normal')
		startButton['state']= NORMAL
		stopButton['state'] = DISABLED

def initPublicPrivateKeys():
	global serverPrivKey,serverPubKey
	serverPrivKey = RSA.import_key(open('serverPrivate.pem', 'r').read())
	serverPubKey = RSA.import_key(open('serverPublic.pem', 'r').read())

def RSAencrypt(plain_text,clientPubKey):
	try: 
		cipher = PKCS1_OAEP.new(key=clientPubKey)
		cipher_text = cipher.encrypt(plain_text)
		return cipher_text
	except Exception as e:
		print(e)

def RSAdecryption(cipher_text):
	global serverPrivKey
	try:
		decrypt = PKCS1_OAEP.new(key=serverPrivKey)
		decrypted_message = decrypt.decrypt(cipher_text)
		return decrypted_message
	except Exception as e:
		return e

clients = {}
addresses = {}
pubKeys = {}
activeConnection = False
server = socket(AF_INET,SOCK_STREAM)

masterServer = Tk()
masterServer.title("Server Application")
masterServer.geometry("750x300+300+300")

frame3= Frame(masterServer,height = 30, width = 45,bg='white')
frame3.pack(side='left',fill=BOTH,expand='true')
listFrame3= Frame(masterServer, width=100, height=100,bg='white')
listFrame3.place(in_=frame3,relx=0.5, rely=0.5, anchor=CENTER)


#Server textbox
frame4= Frame(masterServer)
frame4.pack(side='right',fill=BOTH,expand='true')
listFrame4= Frame(masterServer, width=200, height=40,bg='white')
listFrame4.place(in_=frame4,relx=0.5, rely=0.5, anchor=CENTER)
scroll=Scrollbar(listFrame4)
#scroll.pack(side=RIGHT,fill=Y)
scroll.grid(row=0,column=1,rowspan=1,sticky=N+S)

msgBox2 = Listbox(listFrame4, height = 10, width = 35,yscrollcommand=scroll.set) #For server
msgBox2.grid(row=0,column=0)

#Server label & entry for Port Number
enteredPortNo = StringVar()
labelPort1=Label(listFrame3, text="Port Number")
labelPort1.grid(row=0,column=0)

textEntryPort1 = Entry(listFrame3,textvariable=enteredPortNo)
# textEntryPort1.bind("<Return>",lambda event, currentEntry=enteredPortNo: receive_port_number(enteredPortNo))
textEntryPort1.grid(row=0,column=1)
enteredPortNo.trace('w',checkConnectInputs)



startButton = Button(listFrame3, text='Start listening',width=12,height=2,bg='grey',fg='black',state=DISABLED)
# startButton.bind("<Button>",lambda event, currentEntry=enteredPortNo: receive_port_number(enteredPortNo))
startButton.bind("<Button>",lambda event,currentEntry=enteredPortNo : None if startButton['state'] == DISABLED else receive_port_number(enteredPortNo)
)

startButton.grid(row=1,column=1)

stopButton = Button(listFrame3, text='Stop listening',width=12,height=2,bg='grey',fg='black',state=DISABLED)
stopButton.bind("<Button>",lambda event : None if stopButton['state'] == DISABLED else terminateConnection())

stopButton.grid(row=2,column=1)
masterServer.protocol("WM_DELETE_WINDOW", window_close)
mainloop()
