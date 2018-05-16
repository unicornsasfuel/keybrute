# Standalone AES key brute forcer by Daniel Crowley, X-Force Red
# Based on AES trial decryption FeatherModule by Daniel Crowley
#

from Crypto.Cipher import AES
import argparse
from binascii import unhexlify
from base64 import b64decode as b64d
from string import rstrip

tool_desc = '''
A wordlist-based AES key brute force utility capable of finding keys by trial decryption
of one or more samples followed by a check for correct decryption involving padding
correctness checks or known plaintext matching.
'''

parser = argparse.ArgumentParser(description='AES key brute forcer')
parser.add_argument('keylist', help='''A list of hex-encoded keys
		    newline separated in a single file, such as the
		    ones produced by the generator scripts.''')
parser.add_argument('sample_file', help='''A list of samples of data
		    encrypted with the same AES key for cracking''')
parser.add_argument('--iv',default=None, help='''A known initialization
		    vector (IV) for decrypting in CBC mode''')
parser.add_argument('-c', '--crib', help='''A string to check for in
		    decrypted data to help identify when the right
		    key may have been found. If not provided, the
		    decrypted data will instead be checked for
		    correct pkcs7 padding.''', default=None)
parser.add_argument('-e', '--encoding', help='''The encoding scheme used
		    on the samples. Can be "hex" or "base64".''',
		    choices=['hex', 'base64'], default='hex')

args = parser.parse_args()

# parse sample file
sample_fh = open(args.sample_file, 'r')
samples = map(rstrip, sample_fh.readlines())
if args.encoding == 'base64':
   samples_decoded = map(b64d, samples)
else:
   samples_decoded = map(unhexlify, samples)
sample_fh.close()

# parse wordlist
keys_fh = open(args.keylist, 'r')
keys = map(rstrip, keys_fh.readlines())
keys = map(unhexlify, keys)
keys_fh.close()



# Perform the actual brute force
def aes_key_brute(samples, keys):
   # Check that the samples are the correct size to match AES
   if not all([len(sample) % 16 == 0 for sample in samples]):
      return False
   

   def decrypt_and_check(cipher, ciphertext):
      '''Branch to correct decrypt and check method based on user args'''
      if args.crib != None:
         return decrypt_and_check_crib(cipher, ciphertext)
      else:
         return decrypt_and_check_pkcs7(cipher, ciphertext)

   def decrypt_and_check_crib(cipher, ciphertext):
      '''Decrypt under constructed cipher and return True or False indicating presence of crib'''
      pt = cipher.decrypt(ciphertext)
      return (args.crib in pt)

   def decrypt_and_check_pkcs7(cipher, ciphertext):
      '''Decrypt under constructed cipher and return True or False indicating correct pkcs7 padding'''
      pt = cipher.decrypt(ciphertext)
      last_byte = ord(pt[-1])
      if last_byte > 16:
         return False
      elif pt[-last_byte:] == chr(last_byte)*last_byte:
         return True
      else:
         return False

   results = []
   
   # filter samples into one-block samples and multi-block samples
   one_block_samples = filter(lambda x: len(x)==16, samples)
   multi_block_samples = filter(lambda x: len(x) > 16, samples)
   
   if len(multi_block_samples) == 1 and args.crib == None:
      print('[*] Only a single multi-block sample exists. This has a 1 in 256 chance of false positives with the CBC test.')
   if len(one_block_samples) == 1 and args.crib == None:
      print('[*] Only a single one-block sample exists. This has a 1 in 256 chance of false positives with the ECB, CBC key-as-IV, and CBC known IV tests.')
   
   for key in keys:
      # set all bad_decryption flags to False
      ecb_bad_decrypt = cbc_key_as_iv_bad_decrypt = cbc_bad_decrypt = cbc_known_iv_bad_decrypt = False

      # ECB
      for sample in samples:
         cipher = AES.new(key, AES.MODE_ECB)
         # If any decryption fails to produce valid padding, flag bad ECB decryption and break
         if args.crib == None:
            sample = sample[-16:]
         if decrypt_and_check(cipher, sample) == False:
            ecb_bad_decrypt = True
            break

      # CBC last block with second to last block as IV
      if len(multi_block_samples) != 0:
         for sample in multi_block_samples:
            if args.crib == None:
               cipher = AES.new(key, AES.MODE_CBC, sample[-32:-16])
               # If any decryption fails to produce valid padding, flag bad CBC decryption and break
               if decrypt_and_check(cipher, sample[-16:]) == False:
                  cbc_bad_decrypt = True
                  break
            elif args.iv != None:
               cipher = AES.new(key, AES.MODE_CBC, unhexlify(args.iv))
               if decrypt_and_check(cipher, sample) == False:
                  cbc_bad_decrypt = True
                  break
            else:
               cipher = AES.new(key, AES.MODE_CBC, key)
               if decrypt_and_check(cipher, sample) == False:
                  cbc_bad_decrypt = True
                  break
               
      else:
         cbc_bad_decrypt = True
      
      if len(one_block_samples) != 0:
         if args.iv != None:
            cbc_key_as_iv_bad_decrypt = True
            # CBC with entered IV
            for sample in one_block_samples:
               cipher = AES.new(key, AES.MODE_CBC, unhexlify(args.iv))
               # If any decryption fails to produce valid padding, flag bad CBC decryption and break
               if decrypt_and_check(cipher, sample) == False:
                  cbc_known_iv_bad_decrypt = True
                  break
         else:
            cbc_known_iv_bad_decrypt = True
            # CBC with key as IV
            for sample in one_block_samples:
               cipher = AES.new(key, AES.MODE_CBC, key)
               # If any decryption fails to produce valid padding, flag bad CBC_key_as_IV decryption and break
               if decrypt_and_check(cipher, sample) == False:
                  cbc_key_as_iv_bad_decrypt = True
                  break
      else:
         cbc_known_iv_bad_decrypt = cbc_key_as_iv_bad_decrypt = True

      if not ecb_bad_decrypt:
         results.append(key.encode('hex') + ' may be the correct key in ECB mode or CBC mode with static all-NUL IV.')
      if not cbc_bad_decrypt:
         results.append(key.encode('hex') + ' may be the correct key in CBC mode, IV unknown.')
      if not cbc_key_as_iv_bad_decrypt:
         results.append(key.encode('hex') + ' may be the correct key and static IV in CBC mode.')
      if not cbc_known_iv_bad_decrypt:
         results.append(key.encode('hex') + ' may be the correct key in CBC mode using the provided IV.')
         
            
   print('Potentially correct AES keys:')
   print('-' * 80)
   print('\n'.join(results))
   return results


# run the brute force
results = aes_key_brute(samples_decoded, keys)
if results == False:
   # TODO: Be more specific
   print('Something went wrong while attempting to brute force.')
