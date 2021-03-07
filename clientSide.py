
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from tkinter import *
from queue import *
from time import *
import threading
import sys
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
from socket import *
import json


def AESencrypt(plain_text):

	global aesKey
	cipher_config = AES.new(aesKey, AES.MODE_GCM)

	cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
	return {
		'cipher_text': b64encode(cipher_text).decode('utf-8'),
		'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
		'tag': b64encode(tag).decode('utf-8') } #Used as MAC here (GMAC)

def AESdecrypt(enc_dict):

	global aesKey
	cipher_text = b64decode(enc_dict['cipher_text'])
	nonce = b64decode(enc_dict['nonce'])
	tag = b64decode(enc_dict['tag'])
	
	cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
	decrypted = cipher.decrypt_and_verify(cipher_text, tag)
	return decrypted

def RSAencrypt(plain_text):
	global serverPubKey
	cipher = PKCS1_OAEP.new(key=serverPubKey)
	try:
		cipher_text = cipher.encrypt(plain_text)
		
		return cipher_text
	except Exception as e:
		print('RSA Encryption Error',e)

def RSAdecryption(cipher_text):
	try:
		decrypt = PKCS1_OAEP.new(key=myPrivKey)
		decrypted_message = decrypt.decrypt(cipher_text)
		return decrypted_message
	except Exception as e:
		print('RSA Decryption Error',e)


def receive():
	global BUFSIZ , Address , client_socket, connection,connection_establishment
	while True:
		if connection:
			try:
				msg_rec = client_socket.recv(BUFSIZ)
		

				if not connection_establishment:
					msg = msg_rec.decode("utf-8")
					if msg == "{code1}":
						m = 'Username or Password Is Incorrect'
						msgBox.insert(END,m)
						msgBox.see(END)
						connection_establishment = False
						connection = False
						terminateConnection()
					elif msg == "{code2}":
						m = 'There is already a connection with given credentials'
						msgBox.insert(END,m)
						msgBox.see(END)
						connection_establishment = False
						connection = False
						terminateConnection()
					elif msg == "{code3}":
						m = 'Successfully connected'
						msgBox.insert(END,m)
						msgBox.see(END)
						connection_establishment = True
						connection = True
						change_gui_state(state=False)
						initPrivateKey(textMsgUsr.get())
				else:
					try:
						msg = msg_rec.decode('utf8')
						print('UTF-MESSAGE')	
						print(msg)
						if msg == "{ServerShutdown}" or msg == "{quit}":
							m = 'Server is Shutting Down'
							print(m)
							msgBox.insert(END,msg)
							msgBox.see(END)
							terminateConnection()
							break	
						elif 'has joined the chat--' in msg or 'has left the chat.--'  in msg:
							m = msg
							print(m)
							msgBox.insert(END,msg)
							msgBox.see(END)
					except:
						pass

					try:
						print(len(msg_rec))
						print('RSA BEGINS')
						received_message = RSAdecryption(msg_rec)
						msg = received_message.decode('utf8')
						print(msg)
						print('RSA ENDS')
						msglist = msg.split(" ",1)
						sender = msglist[0]
						msg = msglist[1]
						print('AES BEGINS')
						decryptedMsg = AESdecrypt(json.loads(msg)).decode('utf-8')
						print(decryptedMsg)
						print('AES ENDS')
						message_to_insert = sender+' '+ decryptedMsg
						msgBox.insert(END,message_to_insert)
						msgBox.see(END)
					except Exception as e:
							print('RECEIVE EXCEPTION',e)
							pass
			except Exception as e:
				print(e) 
			except OSError as ose:
				print(ose)
				break

def send(event=None):
	global client_socket,first_connection,connection
	if connection:
		if first_connection:
			msg = bytes((textMsgUsr.get()+':'+textMsgPass.get()),'utf-8')
			send_message = RSAencrypt(msg)
			print('Logging in with username: ',textMsgUsr.get(),'....')
			client_socket.send(send_message)
			first_connection = False
		else:
			msg = textMsgBox.get()
			if msg != None and msg != '':
				msg = bytes(json.dumps(AESencrypt(msg)),'utf-8') #
				send_message = RSAencrypt(msg)
				textMsgBox.set("")  
				client_socket.send(send_message)

def window_close(event=None): #When you close the window this is called
	global BUFSIZ , Address , client_socket, connection
	if connection:
		msg = "{quit}"
		client_socket.send(bytes(msg, "utf8"))
		client_socket.close()
		connection = False
	connection = False
	masterClient.destroy()

def server_connection(host,port):
	global BUFSIZ , Address , client_socket,connection,first_connection
	if not connection:
		first_connection = True
		BUFSIZ = 2560
		Address = (host, port)
		client_socket = socket(AF_INET, SOCK_STREAM)
		client_socket.connect(Address)
		change_gui_state(state=False)
		try:
			connection = True
			send()
		except Exception as e:
			print('Patladı', e)
		receive_thread = threading.Thread(target=receive)
		receive_thread.daemon = True
		receive_thread.start()

def terminateConnection():
	global BUFSIZ , Address , client_socket,connection,first_connection,connection_establishment
	if connection_establishment:
		if connection:
			msg = "{quit}"
			client_socket.send(bytes(msg, "utf8"))
			client_socket.close()
			connection = False
			first_connection = True
			change_gui_state(state=True)
			m = 'Connection Terminated'
			msgBox.insert(END,m)
			msgBox.see(END)
			connection_establishment = False
		connection = False
		connection_establishment = False
	else:
		connection = False
		client_socket.close()
		first_connection = True
		change_gui_state(state=True)


def writeToBox(currentEntry):
	global textEntryCheckVar
	m = currentEntry.get()
	if m != "" and textEntryCheckVar :
		msgBox.insert(END,m)
		msgBox.see(END)
		currentEntry.set("")
		
def clearText(event):
	global textEntryCheckVar
	m = textMsgBox.get()
	textEntryCheckVar = True
	if m != "" :
		textMsgBox.set("")


def connect(connectionParams):
	global connection
	if not connection:
		connectionParameterList = [param.get() for param in connectionParams]	
		try:
			host = str(connectionParameterList[0])
			port = int(str(connectionParameterList[1]))
			server_connection(host=host, port=port)
		except Exception as e:
			change_gui_state(state=True)
			m = 'Connection refused or server is down'
			msgBox.insert(END,m)
			msgBox.see(END)	
			print(e)
	else:
		m = 'There is already an active connection'
		msgBox.insert(END,m)
		msgBox.see(END)

def checkConnectInputs(*arg):
	global userinfoEntryVar,textMsgIP,textMsgPort1,textMsgUsr,textMsgPass
	if userinfoEntryVar:
		m1=len(textMsgIP.get().strip()) > 8
		m2=len(textMsgPort1.get().strip()) > 1
		m3=len(textMsgUsr.get().strip()) > 5
		m4=len(textMsgPass.get().strip())> 5
		if m1 and m2 and m3 and m4:
			connectButton.configure(state="normal")
		else:
			connectButton.configure(state="disable")

def checkEntryBar(*arg):
	m = textMsgBox.get().strip()
	if m == "":
		sendButton.configure(state="disabled")
	else:
		sendButton.configure(state="normal")

def change_gui_state(state):

	if state == False:
		connectButton.configure(state="disable")
		disconnectButton.configure(state="normal")
		textEntryIP.config(state='disabled')
		textEntryPort1.config(state='disabled')
		textEntryUsr.config(state='disabled')
		textEntryPass.config(state='disabled')

	if state == True:
		connectButton.configure(state="normal")
		disconnectButton.configure(state="disable")
		textEntryIP.config(state='normal')
		textEntryPort1.config(state='normal')
		textEntryUsr.config(state='normal')
		textEntryPass.config(state='normal')

def initPrivateKey(me):
	global myPrivKey
	myPrivKey = RSA.import_key(open('userPrivate/%sPrivate.pem'%me, 'r').read())

	# pu_key = RSA.import_key(open('/userPrivate/%sPublic.pem'%me, 'r').read())
	# myPrivKey = RSA.generate(bits) #Lenght bits
	# myPubKey = myPrivKey.publickey()


	


client_socket = socket(AF_INET, SOCK_STREAM)

masterClient = Tk()
masterClient.title("Client App")
masterClient.geometry("750x300+300+300") #750*250 = Window Size, 300+300 = Location in pixels fron top and left
frame1= Frame(masterClient,height = 30, width = 45) 
frame1.pack(side='left',fill=BOTH,expand='true')
listFrame1= Frame(width=100, height=100,bg='white')
listFrame1.place(in_=frame1,relx=0.5, rely=0.5, anchor=CENTER)
#Client textbox and button 
frame2= Frame(masterClient) 
frame2.pack(side='right',fill=BOTH,expand='true')
listFrame2= Frame(width=200, height=40,bg='white')
listFrame2.place(in_=frame2,relx=0.5, rely=0.5, anchor=CENTER)
#Scroll definition for Client
scroll=Scrollbar(listFrame2)
#scroll.pack(side=RIGHT,fill=Y)
scroll.grid(row=0,column=1,rowspan=1,sticky=N+S)
#Message box definition
msgBox = Listbox(listFrame2, height = 10, width = 35, yscrollcommand=scroll.set) #For client
scroll.config(command=msgBox.yview) #helps to work scroolbar properly	
msgBox.grid(row=0,column=0)
textMsgIP = StringVar()
textMsgPort1 = StringVar()
textMsgUsr = StringVar()
textMsgPass = StringVar()
	#Client Label & Entry for IP Address
labelIP=Label(listFrame1, text="IP Address")
labelIP.grid(row=0,column=0)
textEntryIP = Entry(listFrame1,textvariable=textMsgIP)
#textEntryIP.bind("<Return>",lambda event, currentEntry=textMsgIP: writeToBox(textMsgIP))
textEntryIP.grid(row=0,column=1)
textMsgIP.trace('w',checkConnectInputs)
#Client Label & Entry for Port Number
userinfoEntryVar = True
labelPort1=Label(listFrame1, text="Port Number")
labelPort1.grid(row=1,column=0)
textEntryPort1 = Entry(listFrame1,textvariable=textMsgPort1)
#textEntryPort1.bind("<Return>",lambda event, currentEntry=textMsgPort1: writeToBox(textMsgPort1)) #Lambda is simpler function call returning the value automatically
textEntryPort1.grid(row=1,column=1)
textMsgPort1.trace('w',checkConnectInputs)
#Client Label & Entry User Name
labelUsr=Label(listFrame1, text="User Name")
labelUsr.grid(row=2,column=0)
textEntryUsr = Entry(listFrame1,textvariable=textMsgUsr)
#textEntryUsr.bind("<Return>",lambda event, currentEntry=textMsgUsr: writeToBox(textMsgUsr))
textEntryUsr.grid(row=2,column=1)
textMsgUsr.trace('w',checkConnectInputs)
#Client Label & Entry for Password
labelPass=Label(listFrame1, text="Password")
labelPass.grid(row=3,column=0)
textEntryPass = Entry(listFrame1,show="*",textvariable=textMsgPass)
#textEntryPass.bind("<Return>",lambda event, currentEntry=textMsgPass: writeToBox(textMsgPass))
textEntryPass.grid(row=3,column=1)
textMsgPass.trace('w',checkConnectInputs)
#Client connect and disconnect button
connectButton = Button(listFrame1, text='Connect',width=10,height=2,bg='grey',fg ='black', state ='disabled')
connectButton.bind("<Button>",lambda event, connectionParams=[textMsgIP,textMsgPort1,textMsgUsr,textMsgPass]: None if connectButton['state'] == DISABLED else connect(connectionParams))
connectButton.grid(row=4,column=1)
disconnectButton = Button(listFrame1, text='Disconnect',width=10,height=2,bg='grey',fg='black',state=DISABLED)
disconnectButton.bind("<Button>",lambda event : None if disconnectButton['state'] == DISABLED else terminateConnection())
disconnectButton.grid(row=5,column=1)
textMsgBox = StringVar()
textMsgBox.set('Enter your message here')
textEntryCheckVar = False
textEntryBox = Entry(listFrame2,textvariable=textMsgBox)
textEntryBox.bind("<FocusIn>",clearText)
textEntryBox.bind("<Return>",lambda event : None if textMsgBox=='' else send())
textEntryBox.grid(row=1,column=0)
textMsgBox.trace("w", checkEntryBar)
#Client send button
sendButton = Button(listFrame2, text='send',width=10,height=2,bg='grey',fg='black',state=DISABLED,command=send)
sendButton.grid(row=2,column=0)

first_connection = True
gui_enable=True
connection =False
connection_establishment = False
aesKey =  b'N\xf6\xd6\xfd\x89\xf0X\xed\xd6\xea\x8f\xb0x\xcb\xdc\x8a\x95\r\x10\xc3\xee@H\x8b\x1e;5\x85\tR\xe9\xe7' #any pre-distributed aes key here
serverPubKey = RSA.import_key(open('serverPublic.pem', 'r').read())

masterClient.protocol("WM_DELETE_WINDOW", window_close)
mainloop()

