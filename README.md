# The JSON Web Token Toolkit v2
>*jwt_tool.py* is a toolkit for validating, forging, scanning and tampering JWTs (JSON Web Tokens).  


Its functionality includes:
* Checking the validity of a token
* Testing for known exploits:
  * (CVE-2015-2951) The ***alg=none*** signature-bypass vulnerability
  * (CVE-2016-10555) The ***RS/HS256*** public key mismatch vulnerability
  * (CVE-2018-0114) ***Key injection*** vulnerability
* Scanning for misconfigurations or known weaknesses
* Fuzzing claim values to provoke unexpected behaviours
* Testing the validity of a secret/key file/Public Key/JWKS key
* Identifying ***weak keys*** via a High-speed ***Dictionary Attack***
* Forging new token header and payload contents and creating a new signature with the **key** or via another attack method
* Timestamp tampering
* RSA and ECDSA key generation, and reconstruction (from JWKS files)
* ...and lots more!

---

## Audience
This tool is written for **pentesters**, who need to check the strength of the tokens in use, and their susceptibility to known attacks. A range of tampering, signing and verifying options are available to help delve deeper into the potential weaknesses present in some JWT libraries.  
It has also been successful for **CTF challengers** - as CTFs seem keen on JWTs at present.  
It may also be useful for **developers** who are using JWTs in projects, but would like to test for stability and for known vulnerabilities when using forged tokens.

---

## Requirements
This tool is written natively in **Python 3** (version 3.6+) using the common libraries, however various cryptographic funtions (and general prettiness/readability) do require the installation of a few common Python libraries.  
*(An older Python 2.x version of this tool is available on the legacy branch for those who need it, although this is no longer be supported or updated)*

---

## Installation
Installation is just a case of downloading the `jwt_tool.py` file (or `git clone` the repo).  
(`chmod` the file too if you want to add it to your *$PATH* and call it from anywhere.)

`$ git clone https://github.com/ticarpi/jwt_tool`  
`$ python3 -m pip install termcolor cprint pycryptodomex requests`  

On first run the tool will generate a config file, some utility files, logfile, and a set of Public and Private keys in various formats.  

### Custom Configs
* To make best use of the scanning options it is **strongly advised** to copy the custom-generated JWKS file somewhere that can be accessed remotely via a URL. This address should then be stored in `jwtconf.ini` as the "jwkloc" value.  
* In order to capture external service interactions - such as DNS lookups and HTTP requests - put your unique address for Burp Collaborator (or other alternative tools such as RequestBin) into the config file as the "httplistener" value.  
***Review the other options in the config file to customise your experience.***

---

## Usage
The first argument should be the JWT itself (*unless providing this in a header or cookie value*). Providing no additional arguments will show you the decoded token values for review.  
`$ python3 jwt_tool.py <JWT>`  

The toolkit will validate the token and list the header and payload values.  

### Additional arguments
The many additional arguments will take you straight to the appropriate function and return you a token ready to use in your tests.  
For example, to tamper the existing token run the following:  
`$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -T`  

Many options need additional values to set options.  
For example, to run a particular type of exploit you need to choose the eXploit (-X) option and select the vulnerability (here using "a" for the *alg:none* exploit):  
`$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -X a`

### Extra parameters
Some options such as Verifying tokens require additional parameters/files to be provided (here providing the Public Key in PEM format):  
`$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -V -pk public.pem`  

### Sending tokens to a web application
All modes now allow for sending the token directly to an application.  
You need to specify:  
* target URL (-t)
* a request header (-rh) or request cookies (-rc) that are needed by the application (***at least one must contain the token***)
* (optional) any POST data (where the request is a POST)
* (optional) any additional jwt_tool options, such as modes or tampering/injection options  
* (optional) a *canary value* (-cv) - a text value you expect to see in a successful use of the token (e.g. "Welcome, ticarpi")  
An example request might look like this (using scanning mode for forced-errors):  
`$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -rh "Origin: null" -cv "Welcome" -M er` 

Various responses from the request are displayed:  
* Response code
* Response size
* Unique request tracking ID (for use with logging)
* Mode/options used

---

## Common Workflow

Here is a quick run-through of a basic assessment of a JWT implementation. If no success with these options then dig deeper into other modes and options to hunt for new vulnerabilities (or zero-days!).  

### Recon:  
Read the token value to get a feel for the claims/values expected in the application:  
`$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw`  

### Scanning:
Run a ***Playbook Scan*** using the provided token directly against the application to hunt for common misconfigurations:  
`$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -M pb`  

### Exploitation:
If any successful vulnerabilities are found change any relevant claims to try to exploit it (here using the *Inject JWKS* exploit and injecting a new username):  
`$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin` 

### Fuzzing:
Dig deeper by testing for unexpected values and claims to identify unexpected app behaviours, or run attacks on programming logic or token processing:  
`$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -I -hc kid -hv custom_sqli_vectors.txt`  

### Review:
Review any successful exploitation by querying the logs to read more data about the request and :  
`$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`   

---

### Help
For a list of options call the usage function:
Some options such as Verifying tokens require additional parameters/files to be provided:  
`$ python3 jwt_tool.py -h`

**A more detailed user guide can be found on the [wiki page](https://github.com/ticarpi/jwt_tool/wiki/Using-jwt_tool).**

---

## JWT Attack Playbook - new wiki content!  
![playbook_logo](https://user-images.githubusercontent.com/57728093/68797806-21f25700-064d-11ea-9baa-c58fb6f75c0b.png)

Head over to the [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki) for a detailed run-though of what JWTs are, what they do, and a full workflow of how to thoroughly test them for vulnerabilities, common weaknesses and unintended coding errors.

---

## Version History/Changelog

### v2.0
* October 2020
* Python 3.x
* MAJOR REWRITE: lots more capabilities and new commandline arguments/flags - docs written and guides published
* [+] Send tokens directly to the web application from jwt_tool, and proxy through existing tools (Burp, ZAP, etc.)
* [+] ALL NEW SCANNING MODE!:
  * Scan for common vulnerabilities from the [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
  * Test for error conditions by forcing invalid content-types in claims
  * Test for unused valid claims by injection
* [+] Customise your default options in the config file
* [+] Built-in dictionaries and assistive lists to find bugs and misconfigurations
* [+] Logging enabled for all tokens, allowing audit, review and re-tampering of successful requests
* [+] Inject token claims and values on-the-fly across all modes, fuzz values from lists, and bruteforce accepted values

### v1.3.5
* October 2020
* Python 3.x
* [+] Enabled reading of multiple-level nesting of JSON objects in claims
* Fixed function names and text referencing 'key length' where it should have been 'hash length'

### v1.3.4
* May 2020
* Python 3.x
* [+] Updated Tamper mode to allow users to input all JSON data types when editing or creating new claims
  * To specify a new JSON object just create a new empty object with curly braces: {}
  * To create a JSON array add it in directly: ['item1','item2']
* [+] General streamlining and bug squashing
* Fixed missing urlsafe_b64 decoding in validateToken()

### v1.3.3
* April 2020
* Python 3.x
* [+] Changed Tamper mode to allow users to specify data type when editing or creating new claims
  * To specify number, true, false, null just type the relevant value
  * To force a string surround the input with double quotes
  * e.g. to include a number as a text string enclose in quotes, or leave without if you want it as a number data type

### v1.3.2
* November 2019
* Python 3.x
* [+] Added ability to provide Private Key for signing in Tamper mode, or via cmdline (`jwt_tool.py [jwt] -S -u URL -pr PRIVKEY.pem`)
* [+] JWKS exported as a file as well as displayed to screen
* [*] Bonus tip - you can verify the JWKS with JWKS Check option ('jwt_tool.py [jwt] -J -jw JWKSFILE.json')

### v1.3.1
* November 2019
* Python 3.x
* [+] Fixed tampering when signing with [3] and [4]

### v1.3
* November 2019
* Python 3.x
* [+] Commandline argument processing for automation
* [+] Support for tampering, signing and verifying all JWT documented algorithms:
  * RS256/RS384/RS512
  * EC256/EC384/EC512
  * PS256/PS384/PS512
* [+] EXPLOIT: Injection of self-signed Public Key (CVE-2018-0114)
* [+] Timestamp parsing
* [+] Expiry check
* [+] Timestamp tampering
* [+] Tamper nested JSON in claim values
* [+] Key generation: RSA, ECDSA
* [+] Key reconstruction from JWKS files: RSA, ECDSA
* [+] Key verification from JWKS files
* [+] JWKS file generation from RSA key pairs
* Bugfixes:
  * Cleaning up code dead-ends and error conditions

### v1.2.1
* October 2019
* Python 3.x
* [+] ADD and DELETE keys/claims from head and payload
* [+] New ASCII art(!)
* [+] Added feedback for long dictionaries - every 1 million passwords
* [+] Added advice for using hashcat when dictionary attack fails
* Bugfixes:
  * Squashed errors on invalid input
  * Patched an issue with dictionary attack, with not UTF-8 words in list.

### v1.2
* October 2019
* Python 3.x  
* [+] Fully converted to Python 3
* [+] Improved menu
* [+] Improved workflow
* [+] Groundwork for some new features coming soon...

### v1.1.1
* October 2019
* Python 2.x  
* Bugfixes:  
  * Corrected the alg=none issue by adding a non-capitalised version to output
  * Fixed excessive load times when using a large dictionary file
  * Other minor tweaks

### v1.1
* June 2018
* Python 2.x  
* [+] Create new header claims
* [+] Sign with key file (kid)  
* [+] Check signature against key file (kid)  
* [+] Output as standard and URL-safe tokens  
* Bugfixes:  
* Fix broken base64 decoding when certain ASCII characters are present  
* Fix broken signature checking/brute-forcing on URL-safe tokens  
* Many other minor tweaks and improvements

### v1.0
* July 2017
* Python 2.x  
* [+] Signature recognition
* [+] Support for HS384, HS512
* [+] EXPLOIT: RSA Public Key mismatch vulnerability (key confusion)
* [+] Improved dictionary attack routine

### v0.1
* January 2017
* Initial release
* Python 2.x
* Tamper existing claims
* EXPLOIT: test for alg:none vulnerability
* Check HS256 key
* Crack with HS256 dictionary attack

---

## Tips
**Regex for finding JWTs in Burp Search**  
*(make sure 'Case sensitive' and 'Regex' options are ticked)*  
`[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*` - url-safe JWT version  
`[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*` - all JWT versions (higher possibility of false positives)

---

## Further Reading
* [JWT Attack Playbook (https://github.com/ticarpi/jwt_tool/wiki)](https://github.com/ticarpi/jwt_tool/wiki) - for a thorough JWT testing methodology

* [A great intro to JWTs - https://jwt.io/introduction/](https://jwt.io/introduction/)

* A lot of the initial inspiration for this tool comes from the vulnerabilities discovered by Tim McLean.  
[Check out his blog on JWT weaknesses here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)  

* A whole bunch of exercises for testing JWT vulnerabilities are provided by [Pentesterlab (https://www.pentesterlab.com)](https://www.pentesterlab.com). I'd highly recommend a PRO subscription if you are interested in Web App Pentesting.  

  *PLEASE NOTE:* This toolkit will solve most of the Pentesterlab JWT exercises in a few seconds when used correctly, however I'd **strongly** encourage you to work through these exercises yourself, working out the structure and the weaknesses. After all, it's all about learning...
