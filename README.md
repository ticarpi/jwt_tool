# JSON Web Token Toolkit
>This is a Python toolkit for handling JWTs (JSON Web Tokens) that are used for authentication/authorisation in hosted web applications.

Its functionality includes:
- Checking the validity of a token
- Testing for the RS-/HS256 public-key mismatch vulnerability
- Testing for the ***alg=None*** signature-bypass technique
- Validating the accuracy of a **key**
- Forging new token payload values and resigning with the **key**
- High-speed Dictionary attack to identify the **key**

## Audience
This tool is written for pentesting engagements, where the tester needs to check the strength of the tokens in use, and their susceptibility to known attacks.
It may also be useful for developers who are using JWTs in projects, but would like to test for stability and for known vulnerabilities, when using forged tokens.

## Requirements
This tool is written natively in Python 2.x and runs well on all systems that support Python.

Customised dictionaries are recommended for the Dictionary attack option.  
As a speed reference, an Intel i5 laptop can test ~1,000,000 passwords per second on HMAC-SHA256 signing. YMMV.

## Usage
Installation is just a case of downloading the `jwt_toolkit.py` file and running it:  
`$ python jwt_toolkit.py`  
The first argument should be the JWT itself, followed by a wordlist filename (if you are trying to crack the token).  

**For example:**  
`$ python jwt_toolkit.py eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJhZG1pbiI6IHRydWUsICJuYW1lIjogInRpY2FycGkifQ.DRkDo/XFb/dJCZXiVOMORxq+gcpA7g50xpwfk3UPrJc rockyou.txt`  

The toolkit will validate the token and enumerate the header and payload values and provide a menu of your available options.  

### Using forged tokens
Any tokens forged in this toolkit can be spoofed by your preferred method - and depending on whether they are set as an HTTP Header value, a cookie, or some other stored value.  
You can use these either by:
- intercepting the token sent to the webserver from your client when in use
- intercepting the original token sent from the webserver on login
- editing the cookie (or stored value) via a browser plugin
- replacing the cookie in the browser console  

All of these are useful methods, but be aware that the first method does not create persistence of the token as it is not stored client-side - therefore refreshing the page will reload the resources with the original token.

## Testing Methodologies  
For pentesting the use of JWT as an authentication method you should test *at least* the following:  

### Signature attacks
- Is the ***alg=None*** vulnerability present?
- Is the signature method validated by the application?
- Is the token **key** guessable, or in a basic wordlist?  
- Is the *public key* able to be reused by passing it as the 'secret' to the HMAC-SHA signature algorithms?

*If so*:  
- Can you spoof usernames to login as another user/admin?  
- Can you tamper with other values to escalate privileges?
- Can you use **key:value** pairs as an injection point?

### Impersonation/Interception
- Is the token protected in transit via TLS?
- Is the token protected against XSS or other client-side attacks?  

*If so*:  
- Can you spoof the captured token from another machine and log in as the token's owner?
