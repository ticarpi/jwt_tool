# The JSON Web Token Toolkit
>*jwt_tool.py* is a toolkit for validating, forging and cracking JWTs (JSON Web Tokens).  


Its functionality includes:
- Checking the validity of a token
- Testing for the ***RS/HS256*** public key mismatch vulnerability
- Testing for the ***alg=none*** signature-bypass vulnerability
- Testing the validity of a secret/key/key file
- Identifying ***weak keys*** via a High-speed ***Dictionary Attack***
- Forging new token header and payload values and creating a new signature with the **key** or via another attack method

---

## Audience
This tool is written for **pentesters**, who need to check the strength of the tokens in use, and their susceptibility to known attacks.  
It has also been successful for **CTF challengers** - as CTFs seem keen on JWTs at present.  
It may also be useful for **developers** who are using JWTs in projects, but would like to test for stability and for known vulnerabilities when using forged tokens.

## Requirements
This tool is written natively in **Python 3** using the common libraries.  
*(An older Python 2.x version is available for those who need it on the legacy branch, although this will no longer be supported or updated - as of October 2019)*

Customised wordlists are recommended for the Dictionary Attack option.  
*As a speed reference, an Intel i5 laptop can test ~1,000,000 passwords per second on HMAC-SHA256 signing. YMMV.*

## Installation
Installation is just a case of downloading the `jwt_tool.py` file (or `git clone`ing the repo).  
(`chmod` the file too if you want to add it to your *$PATH* and call it from anywhere.)

## Usage
`$ python3 jwt_tool.py <JWT> (filename)`  

The first argument should be the JWT itself, followed by a filename/filepath (for cracking the token, or for use as a key file).  

**For example:**  
`$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw /usr/share/wordlists/rockyou.txt`  

The toolkit will validate the token and list the header and payload values.  
It will then provide a menu of your available options.  
*Note:* signing forged tokens is currently only supported using HS256, HS384, HS512 algorithms

Input is in either standard or url-safe JWT format, and the resulting tokens are output in both formats for your ease of use.


## Further Reading
* [A great intro to JWTs - https://jwt.io/introduction/](https://jwt.io/introduction/)

* A lot of the inspiration for this tool comes from the vulnerabilities discovered by Tim McLean.  
[Check out his blog on JWT weaknesses here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)  

* My introduction to using this toolkit, and a bit of the history behind it can be found [on my blog - https://www.ticarpi.com/introducing-jwt-tool/](https://www.ticarpi.com/introducing-jwt-tool/)

* A whole bunch of exercises for testing JWT vulnerabilities are provided by [Pentesterlab](https://www.pentesterlab.com). I'd highly recommend a PRO subscription if you are interested in Web App Pentesting.  
  * [JWT (alg=None vulnerability) exercise](https://pentesterlab.com/exercises/jwt)  
  * [JWT_II (RS/HS256 public key mismatch vulnerability) exercise](https://pentesterlab.com/exercises/jwt_ii)  
  * [JWT_III (key-id header field non-sanitisation vulnerability) exercise](https://pentesterlab.com/exercises/jwt_iii)  
  * and many more...
  * and just head on over to [https://pentesterlab.com/exercises](https://pentesterlab.com/exercises) to search for the others!

  *PLEASE NOTE:* This toolkit will solve most of the Pentesterlab JWT exercises in a few seconds when used correctly, however I'd **strongly** encourage you to work through these exercises yourself, working out the structure and the weaknesses. After all, it's all about learning...

## Tips
**Regex for finding JWTs in Burp Search**  
*(make sure 'Case sensitive' and 'Regex' options are ticked)*  
`[= ]ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*` - url-safe JWT version  
`[= ]ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*` - all JWT versions (higher possibility of false positives)
