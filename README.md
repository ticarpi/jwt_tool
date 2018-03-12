# The JSON Web Token Toolkit
>*jwt_tool.py* is a toolkit for validating, forging and cracking JWTs (JSON Web Tokens).  


Its functionality includes:
- Checking the validity of a token
- Testing for the ***RS/HS256*** public key mismatch vulnerability
- Testing for the ***alg=None*** signature-bypass vulnerability
- Testing the validity of a secret/key
- Identifying ***weak keys*** via a High-speed ***Dictionary Attack*** 
- Forging new token payload values and resigning with the **key** (for the HMAC-SHA family of algorithms)

---

## Audience
This tool is written for **pentesters**, who need to check the strength of the tokens in use, and their susceptibility to known attacks.  
It may also be useful for **developers** who are using JWTs in projects, but would like to test for stability and for known vulnerabilities, when using forged tokens.

## Requirements
This tool is written natively in Python 2.x using the common libraries.

Customised wordlists are recommended for the Dictionary Attack option.  
*As a speed reference, an Intel i5 laptop can test ~1,000,000 passwords per second on HMAC-SHA256 signing. YMMV.*

## Installation
Installation is just a case of downloading the `jwt_tool.py` file (or `git clone`ing the repo).  
(`chmod` the file too if you want to add it to your *$PATH* and call it from anywhere.)

## Usage
`$ python jwt_tool.py <JWT> (wordlist_file)`  

The first argument should be the JWT itself, followed by a wordlist filename (if you are trying to crack the token).  

**For example:**  
`$ python jwt_tool.py eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJhZG1pbiI6IHRydWUsICJuYW1lIjogInRpY2FycGkifQ.DRkDo/XFb/dJCZXiVOMORxq+gcpA7g50xpwfk3UPrJc rockyou.txt`  

The toolkit will validate the token and list the header and payload values.  
It will then provide a menu of your available options.  

## Further Reading
* [A great intro to JWTs - https://jwt.io/introduction/](https://jwt.io/introduction/)


* A lot of the inspiration for this tool comes from the vulnerabilities discovered by Tim McLean.  
[Check out his blog on JWT weaknesses here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)  

* My introduction to using this toolkit, and a bit of the history behind it can be found [on my blog - https://www.ticarpi.com/introducing-jwt-tool/](https://www.ticarpi.com/introducing-jwt-tool/)

* A couple of exercises for testing JWT vulnerabilities are provided by [Pentesterlab](https://www.pentesterlab.com). I'd highly recommend a PRO subscription if you are interested in Web App Pentesting.  
  * [JWT (alg=None vulnerability) exercise](https://pentesterlab.com/exercises/jwt)  
  * [JWT_II (RS/HS256 public key mismatch vulnerability) exercise](https://pentesterlab.com/exercises/jwt_ii)  
  * [JWT_III (key-id header field non-sanitisation vulnerability) exercise](https://pentesterlab.com/exercises/jwt_iii)  
  
  *PLEASE NOTE:* This toolkit will solve the Pentesterlab JWT exercises in a few seconds when used correctly, however I'd **strongly** encourage you to work through these exercises yourself, working out the structure and the weaknesses. After all, it's all about learning...
