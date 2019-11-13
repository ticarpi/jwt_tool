# The JSON Web Token Toolkit
>*jwt_tool.py* is a toolkit for validating, forging and cracking JWTs (JSON Web Tokens).  


Its functionality includes:
* Checking the validity of a token
* Testing for known exploits:
  * (CVE-2015-2951) The ***alg=none*** signature-bypass vulnerability (CVE-2015-2951)
  * (CVE-2016-10555) The ***RS/HS256*** public key mismatch vulnerability
  * (CVE-2018-0114) ***Key injection*** vulnerability
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
This tool is written natively in **Python 3** using the common libraries, however the cryptographic funtions do require the installation of the `pycryptodomex` Python library.  
*(An older Python 2.x version is available for those who need it on the legacy branch, although this will no longer be supported or updated - as of October 2019)*

---

## Installation
Installation is just a case of downloading the `jwt_tool.py` file (or `git clone`ing the repo).  
(`chmod` the file too if you want to add it to your *$PATH* and call it from anywhere.)

`$ git clone https://github.com/ticarpi/jwt_tool`  
`$ pip3 install pycryptodomex`  

---

## Usage
The first argument should be the JWT itself. Providing no additional arguments will take you to the interactive menu.
`$ python3 jwt_tool.py <JWT>`  

The toolkit will validate the token and list the header and payload values.  
It will then provide a menu of your available options.  

Input is in either standard or url-safe JWT format, and the resulting tokens are output in both formats for your ease of use.

### Additional arguments
The many additional arguments will take you straight to the appropriate function and return you a token ready to use in your tests.  
For example, to test the alg:none exploit run the following:  
`$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -A`

### Extra parameters
Some options such as Verifying tokens require additional parameters/files to be provided:  
`$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -V -pk public.pem`  

### Help
For a list of options call the usage function:
Some options such as Verifying tokens require additional parameters/files to be provided:  
`$ python3 jwt_tool.py -h`

**A more detailed user guide can be found on the [wiki page](https://github.com/ticarpi/jwt_tool/wiki/Usingjwt_tool).**

---

## JWT Attack Playbook - new wiki content!  

Head over to the [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki) for a detailed run-though of what JWTs are, what they do, and a full workflow of how to thoroughly test them for vulnerabilities, common weaknesses and unintended coding errors.

---

## Version History/Changelog

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
