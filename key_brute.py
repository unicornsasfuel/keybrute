# Standalone encryption key brute forcer by Daniel Crowley, X-Force Red
# Based on AES trial decryption FeatherModule by Daniel Crowley
#

from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto.Cipher import AES
import argparse
from binascii import unhexlify
from base64 import b64decode as b64d
from string import rstrip
import sys

tool_desc = '''
A wordlist-based encryption key brute force utility capable of finding keys by trial decryption
of one or more samples followed by a check for correct decryption involving padding
correctness checks or known plaintext matching.
'''

parser = argparse.ArgumentParser(description='Encryption key brute forcer')
parser.add_argument('keylist', help='''A list of hex-encoded keys
		    newline separated in a single file, such as the
		    ones produced by the generator scripts.''')
parser.add_argument('sample_file', help='''A list of samples of data
		    encrypted with the same encryption key for cracking''')
parser.add_argument('-a', '--algorithm', default='AES', choices=['AES',
            '3DES','DES'],help='''The encryption algorithm used to encrypt
            the samples''')
parser.add_argument('-m', '--mode', default=None, help='''The block cipher
            mode of operation to use, if known.''')
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
parser.add_argument('-o','--output', default=None, help='''If specified, a key file
            will be written with the provided name containing all keys
            that produced successful decryption.''')

args = parser.parse_args()

# parse sample file
sample_fh = open(args.sample_file, 'r')
samples = map(rstrip, sample_fh.readlines())
if args.encoding == 'base64':
   samples_decoded = map(b64d, samples)
else:
   samples_decoded = map(unhexlify, samples)
sample_fh.close()

# prepare constants
if args.algorithm == 'AES':
   blocksize = 16
   keysize = 16
elif args.algorithm == 'DES':
   blocksize = 8
   keysize = 8
elif args.algorithm == '3DES': #TODO: support 2-key EDE
   blocksize = 8
   keysize = 24
else:
   raise ValueError('Specified algorithm is unsupported')

# prepare output file
if args.output != None:
   output_fh = open(args.output, 'a')

blocksizex2 = 2 * blocksize #probably unnecessary optimization but we save multiply operations

# prepare mode selection
do_ecb = args.mode in [None, 'ECB']
do_cbc = args.mode in [None, 'CBC']

# Prepare cipher in ECB mode
def prepare_ecb(key):
   if args.algorithm == 'AES':
      cipher = AES.new(key, AES.MODE_ECB)
      return cipher
   elif args.algorithm == 'DES':
      cipher = DES.new(key, DES.MODE_ECB)
      return cipher
   elif args.algorithm == '3DES':
      try:
         cipher = DES3.new(key, DES3.MODE_ECB)
      except ValueError:
         cipher = DES.new(key[:8], DES.MODE_ECB)
      return cipher

# Prepare cipher in CBC mode
def prepare_cbc(key, iv):
   if args.algorithm == 'AES':
      cipher = AES.new(key, AES.MODE_CBC, iv)
      return cipher
   elif args.algorithm == 'DES':
      cipher = DES.new(key, DES.MODE_CBC, iv)
      return cipher
   elif args.algorithm == '3DES':
      try:
         cipher = DES3.new(key, DES3.MODE_CBC, iv)
      except ValueError:
         cipher = DES.new(key[:8], DES.MODE_CBC, iv[:8])
      return cipher


# Perform the actual brute force
def key_brute(samples):
   # Check that the samples are the correct size
   if not all([len(sample) % blocksize == 0 for sample in samples]):
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
      if last_byte > blocksize:
         return False
      elif pt[-last_byte:] == chr(last_byte)*last_byte:
         return True
      else:
         return False

   results = []
   
   # filter samples into one-block samples and multi-block samples
   one_block_samples = filter(lambda x: len(x) == blocksize, samples)
   multi_block_samples = filter(lambda x: len(x) > blocksize, samples)
   
   if len(multi_block_samples) == 1 and args.crib == None:
      print('[*] Only a single multi-block sample exists. This has a 1 in 256 chance of false positives with the CBC test.')
   if len(one_block_samples) == 1 and args.crib == None:
      print('[*] Only a single one-block sample exists. This has a 1 in 256 chance of false positives with the ECB, CBC key-as-IV, and CBC known IV tests.')
   
   # parse wordlist
   with open(args.keylist, 'r') as keys_fh:
      keys = keys_fh.readlines(100000)
      num_keys = 0
      num_candidate_keys = 0
      while keys:
         num_keys += 100000
         sys.stdout.write('\rNumber of keys processed: %d | Number of candidate keys: %d' % (num_keys, num_candidate_keys))
         sys.stdout.flush()
         keys = map(rstrip, keys)
         keys = map(unhexlify, keys)
         for key in keys:
            if len(key) != keysize:
               print("Bad key size, skipping key...")
               continue
            # set all bad_decryption flags to False
            ecb_bad_decrypt = cbc_key_as_iv_bad_decrypt = cbc_bad_decrypt = cbc_known_iv_bad_decrypt = False

            # ECB
            if do_ecb:
               for sample in samples:
                  cipher = prepare_ecb(key)
                  # If any decryption fails to produce valid padding, flag bad ECB decryption and break
                  if args.crib == None:
                     sample = sample[-blocksize:]
                  if decrypt_and_check(cipher, sample) == False:
                     ecb_bad_decrypt = True
                     break
            else:
               ecb_bad_decrypt = True

            # CBC last block with second to last block as IV
            if do_cbc:
               if len(multi_block_samples) != 0:
                  for sample in multi_block_samples:
                     if args.crib == None:
                        cipher = prepare_cbc(key, sample[-blocksizex2:-blocksize])
                        # If any decryption fails to produce valid padding, flag bad CBC decryption and break
                        if decrypt_and_check(cipher, sample[-blocksize:]) == False:
                           cbc_bad_decrypt = True
                           break
                     elif args.iv != None:
                        cipher = prepare_cbc(key, unhexlify(args.iv))
                        if decrypt_and_check(cipher, sample) == False:
                           cbc_bad_decrypt = True
                           break
                     else:
                        cipher = prepare_cbc(key, key)
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
                        cipher = prepare_cbc(key, unhexlify(args.iv))
                        # If any decryption fails to produce valid padding, flag bad CBC decryption and break
                        if decrypt_and_check(cipher, sample) == False:
                           cbc_known_iv_bad_decrypt = True
                           break
                  else:
                     cbc_known_iv_bad_decrypt = True
                     # CBC with key as IV
                     for sample in one_block_samples:
                        cipher = prepare_cbc(key,  key)
                        # If any decryption fails to produce valid padding, flag bad CBC_key_as_IV decryption and break
                        if decrypt_and_check(cipher, sample) == False:
                           cbc_key_as_iv_bad_decrypt = True
                           break
               else:
                  cbc_known_iv_bad_decrypt = cbc_key_as_iv_bad_decrypt = True

            else:
               cbc_bad_decrypt = cbc_key_as_iv_bad_decrypt = cbc_known_iv_bad_decrypt = True

            if any([not ecb_bad_decrypt, not cbc_bad_decrypt, not cbc_key_as_iv_bad_decrypt, not cbc_known_iv_bad_decrypt]):
               num_candidate_keys += 1
               if args.output:
                  output_fh.write(key.encode('hex') + '\n')
               if not ecb_bad_decrypt:
                  results.append(key.encode('hex') + ' may be the correct key in ECB mode or CBC mode with static all-NUL IV.')
               if not cbc_bad_decrypt:
                  results.append(key.encode('hex') + ' may be the correct key in CBC mode, IV unknown.')
               if not cbc_key_as_iv_bad_decrypt:
                  results.append(key.encode('hex') + ' may be the correct key and static IV in CBC mode.')
               if not cbc_known_iv_bad_decrypt:
                  results.append(key.encode('hex') + ' may be the correct key in CBC mode using the provided IV.')
         keys = keys_fh.readlines(100000)

   print('Potentially correct encryption keys:')
   print('-' * 80)
   print('\n'.join(results))
   return results


# run the brute force
results = key_brute(samples_decoded)
if results == False:
   # TODO: Be more specific
   print('Something went wrong while attempting to brute force.')

if args.output:
   output_fh.close()
