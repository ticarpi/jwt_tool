# JSON Web Token Toolkit
>This is a simple Python toolkit for handling JWTs (JSON Web Tokens) that are used for authentication/authorisation in hosted web applications.

Its functionality includes:
- Checking the validity of a token
- Testing for the ***alg=None*** signature-bypass technique
- Validating the accuracy of a provided token **key**
- Forging new token payload values and resigning with the **key**
- Multi-threaded Dictionary attack to identify the token **key**

## Requirements
This tool is written natively in Python 2.7
Runs well on all systems that support Python.

For the Dictionary attack I would recommend using a high-powered, multicore CPU. For reference this runs at ~1500 h/s on an Intel i5 reference laptop. Your mileage may vary.  
Customised dictionaries are recommended.  
***Note:*** a Bruteforce function was considered for this toolkit, but based on the intensity of this process was left out. The use of dedicated cracking software is recommended for use when basic dictionary attacks are not successful.

## Usage
Installation is just a case of downloading the `jwt_toolkit.py` file and running it:  
`$ python jwt_toolkit.py`  
The first argument should be the JWT itself, followed by a wordlist filename (if you are trying to crack the token).  

**For example:**  
`$ python jwt_toolkit.py eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJhZG1pbiI6IHRydWUsICJuYW1lIjogInRpY2FycGkifQ.DRkDo/XFb/dJCZXiVOMORxq+gcpA7g50xpwfk3UPrJc rockyou.txt`  

The toolkit will validate the token and enumerate the header and payload values and provide a menu of your available options.  

### Using forged tokens
Any tokens forged in this toolkit can be spoofed by your preferred method.  
Assuming client-side pentesting as the vector, you can do this either by:
- intercepting the token sent to the webserver from your client when in use
- intercepting the original token sent from the webserver on login
- editing the cookie (or stored value) via a browser plugin
- replacing the cookie in the browser console  

All of these are useful, but be aware that the first method does not create persistence of the token as it is not stored client-side - therefore refreshing the page will reload the resources with the original token.

### [1] Check CVE-2015-2951
This option will generate a forged token to test the webserver's vulnerability to the alg=None signature bypass attack.  
(*Lots of detail is provided about this vulnerability at this [auth0.com vuln page](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/).*)  

In short:
- hit this option to regenerate your existing token but refactored with the signature bypass.  
- Spoof this in your browser and refresh the page - if the session stays logged in then the webserver is likely vulnerable to this attack.  
- You can now use the *Tamper token* menu option to forge new tokens and use the no-signature option once you're done.

### [2] Check signature against a known key
This option allows you to provide a **key** and check that the token validates.  
It may also be helpful to use this option when you've forged a token and want to check that it validates fine client-side before sending it to the webserver.

### [3] Crack signature with a dictionary file
An extension of the above key-verification option.  
This will take the supplied wordlist file from the commandline argument and check each key sequentially using the relevant encryption scheme until it finds a match.  

The faster the CPU the faster this will work, but note that it is a simple process, not optimised for your architecture. As such it is best used with customised or short wordlists.
For bruteforce, or exhaustive wordlists, you may wish to use [John the Ripper](https://github.com/magnumripper/JohnTheRipper) or [Hashcat](https://github.com/hashcat/hashcat).

### [4] Tamper with payload data
This option will list all the payload **key:value** pairs and allow you to edit any value you wish.
   
Select the number assigned to any key and type in your preferred value.  
Once you have finished editing values select `option '0'` to continue on to the signing step.  
You now have two options:
- Sign with an existing **key** - if you already know the **key** in use by the webserver.
- Use the ***alg=None*** vulnerability to bypass signature verification.  

Once signed you can spoof the token in the browser and your new values will be used.

## Testing Methodologies  
For pentesting the use of JWT as an authentication method you should test *at least* the following:  

### Signature attacks
- Is the ***alg=None*** vulnerability present?
- Is the signature method validated by the application?
- Is the token **key** guessable, or in a basic wordlist?  

*If so*:  
- Can you spoof usernames to login as another user/admin?  
- Can you tamper with other values to escalate privileges?
- Can you use **key:value** pairs as an injection point?

### Impersonation/Interception
- Is the token protected in transit via TLS?
- Is the token protected against XSS or other client-side attacks?  

*If so*:  
- Can you spoof the captured token from another machine and log in as the token's owner?

