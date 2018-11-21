# keybrute

This is a tool for cracking encryption keys using captured encrypted data, adapted from the FeatherDuster AES cracking module to be a standalone tool.

keybrute expects Python 2.7 and supports PyPy. This is mostly a proof of concept tool that will be deprecated once a rewrite in a language that can properly parallelize tasks can be written for performance reasons.

You'll need to capture at least one encrypted message. If possible, capture multiple unique encrypted messages produced with the same key. Place them, newline-separated and hex- or base64-encoded, into a single file.

Next, you'll need a list of keys to try. A keylist based off of the password list included with John the Ripper and repeating bytes is included. You can generate your own by taking your favorite password cracking wordlist (rockyou, anyone?) and running it through `convert_wordlist.py` like so:

`python ./convert_wordlist.py -nrm wordlist.txt keylist.txt`

Now you can crack your file of samples. If you provide a crib, every sample will be checked for this crib. If any of your samples do not contain your provided crib once decrypted, the key, even if correct, will not be identified as such. If you do not provide a crib, samples will be checked for the presence of pkcs7 padding. If any decrypted samples are improperly pkcs7 padded, the key being tested, even if correct, will not be identified as correct.

When specifying a crib, ciphertexts are decrypted in their entirety. Otherwise, only the last block of the ciphertext will be decrypted for speed. If working with very large ciphertexts, you should not specify a crib, and generate a list of potentially correct keys to use in another round of cracking using your crib.

For CBC-mode ciphertext, you can provide an IV to be used if it is known.

You can choose from several different ciphers. Currently keybrute supports the following ciphers:

```buildoutcfg
AES
DES
3DES
```

If you'd like to write the list of candidate keys to a file, you can use the `-o` or `--output` option to specify a file name. The output format is a list of hex-encoded keys, suitable for use with keybrute.

## Examples
####Basic usage
The key cracking script can be invoked like so:

`pypy ./key_brute.py keylist.txt sample.txt`

This will default to AES cracking with no known IV, with keys validated based on PKCS7 padding correctness.

####Advanced usage
Using all the options looks like this:

`pypy ./key_brute.py -o outfile -a 3DES --iv 0102010201020102 --crib Password1 -e base64 keylist.txt sample.txt`

This will crack the base64-encoded samples in `sample.txt` with 3DES using keys from `keylist.txt` and the specified IV, and will record any key that produces decrypted data containing `Password1` to the file `outfile`.