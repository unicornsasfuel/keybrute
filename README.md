#AESbrute

This is a tool for cracking AES keys using captured encrypted data, adapted from the FeatherDuster AES cracking module to be a standalone tool.

You'll need to capture at least one encrypted message. If possible, capture multiple unique encrypted messages produced with the same key. Place them, newline-separated and hex- or base64-encoded, into a single file.

Next, you'll need a list of keys to try. You can generate one by taking your favorite password cracking wordlist (rockyou, anyone?) and running it through `convert_wordlist.py` like so:

`python ./convert_wordlist.py -nrm wordlist.txt keylist.txt`

Now you can crack your file of samples. If you provide a crib, every sample will be checked for this crib. If any of your samples do not contain your provided crib once decrypted, the key, even if correct, will not be identified as such. If you do not provide a crib, samples will be checked for the presence of pkcs7 padding. If any decrypted samples are improperly pkcs7 padded, the key being tested, even if correct, will not be identified as correct.

For CBC-mode ciphertext, you can provide an IV to be used if it is known.

The AES cracking script can be invoked like so:

`python ./aes_brute.py keylist.txt sample.txt`
