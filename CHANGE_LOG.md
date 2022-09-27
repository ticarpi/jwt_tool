# Version History/Changelog

## v2.2.2
* February 2021
* Python 3.x
* [+] Send original token when targeturl present
* [+] Send Query token when targeturl present
* Bugfixes:
  * fixed request header split - error on multiple colons
  * fixed error in signing syntax: `ec256` vs `es256`
  * fixed timestamp calculations
  * sign with manual private key reinstated

## v2.2.1
* January 2021
* Python 3.x
* [+] New scan test (re-signing of tokens with common passwords) in 'Playbook' scan mode (`-M pb`)
* [+] Added new hard-coded secret from CVE-2020-1764 to jwt-common.txt

## v2.2.0
* December 2020
* Python 3.x
* [+] NEW exploit: blank password in signature (`-X b`)
* [+] NEW 'bare' mode: return only tokens to stdout - for using with upcoming integrations (`-b`)
* [+] additional checks in 'Playbook' scan mode (`-M pb`)
* [+] reordered help options to group similar options
* Bugfixes:
  * fixed Playbook scanner glitches
  * fixed config file generation issues

## v2.1.0
* November 2020
* Python 3.x
* [+] NEW exploit: null signature (`-X n`)
* [+] NEW scanner mode: Inject Common Claims (`-M cc`)
* [+] additional checks in 'Playbook' scan mode (`-M pb`)
* [+] multiple custom headers now supported (`-rh`)
* [+] reflective JWKS URL created automatically in config file - for JKU/Spoof JWKS attacks (`-X s`)
* [+] checks added for old/incompatible config files
* [+] report on long HTTP response times
* Bugfixes:
  * fixed colours not working in Windows cmd/Powershell
  * fixed capitalisation issue in config file
  * fixed broken null signed kid attacks in ScanModePlaybook()

## v2.0
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

## v1.3.5
* October 2020
* Python 3.x
* [+] Enabled reading of multiple-level nesting of JSON objects in claims
* Fixed function names and text referencing 'key length' where it should have been 'hash length'

## v1.3.4
* May 2020
* Python 3.x
* [+] Updated Tamper mode to allow users to input all JSON data types when editing or creating new claims
  * To specify a new JSON object just create a new empty object with curly braces: {}
  * To create a JSON array add it in directly: ['item1','item2']
* [+] General streamlining and bug squashing
* Fixed missing urlsafe_b64 decoding in validateToken()

## v1.3.3
* April 2020
* Python 3.x
* [+] Changed Tamper mode to allow users to specify data type when editing or creating new claims
  * To specify number, true, false, null just type the relevant value
  * To force a string surround the input with double quotes
  * e.g. to include a number as a text string enclose in quotes, or leave without if you want it as a number data type

## v1.3.2
* November 2019
* Python 3.x
* [+] Added ability to provide Private Key for signing in Tamper mode, or via cmdline (`jwt_tool.py [jwt] -S -u URL -pr PRIVKEY.pem`)
* [+] JWKS exported as a file as well as displayed to screen
* [*] Bonus tip - you can verify the JWKS with JWKS Check option ('jwt_tool.py [jwt] -J -jw JWKSFILE.json')

## v1.3.1
* November 2019
* Python 3.x
* [+] Fixed tampering when signing with [3] and [4]

## v1.3
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

## v1.2.1
* October 2019
* Python 3.x
* [+] ADD and DELETE keys/claims from head and payload
* [+] New ASCII art(!)
* [+] Added feedback for long dictionaries - every 1 million passwords
* [+] Added advice for using hashcat when dictionary attack fails
* Bugfixes:
  * Squashed errors on invalid input
  * Patched an issue with dictionary attack, with not UTF-8 words in list.

## v1.2
* October 2019
* Python 3.x
* [+] Fully converted to Python 3
* [+] Improved menu
* [+] Improved workflow
* [+] Groundwork for some new features coming soon...

## v1.1.1
* October 2019
* Python 2.x
* Bugfixes:
  * Corrected the alg=none issue by adding a non-capitalised version to output
  * Fixed excessive load times when using a large dictionary file
  * Other minor tweaks

## v1.1
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

## v1.0
* July 2017
* Python 2.x
* [+] Signature recognition
* [+] Support for HS384, HS512
* [+] EXPLOIT: RSA Public Key mismatch vulnerability (key confusion)
* [+] Improved dictionary attack routine

## v0.1
* January 2017
* Initial release
* Python 2.x
* Tamper existing claims
* EXPLOIT: test for alg:none vulnerability
* Check HS256 key
* Crack with HS256 dictionary attack
