import argparse
from binascii import hexlify
from md5 import md5

#===========
# Arguments
#===========

parser = argparse.ArgumentParser(description='''A utility for converting a traditional
				 wordlist into a list of hex-encoded keys in various
				 common ways. This utility does not de-duplicate and
				 some key derivation methods may, in certain cases,
				 produce identical outputs.''')
parser.add_argument('-n','--nullpad', action='store_true', help='''Derive keys from
		    passwords by adding null bytes to pad to the key length, or
		    truncating at the key length.''')
parser.add_argument('-r','--repeat', action='store_true', help='''Derive keys from
		    passwords by repeating the bytes of the password to pad to the key
		    length, or truncate at the key length.''')
parser.add_argument('-m','--md5', action='store_true', help='''Derive keys from
		    passwords by using a single iteration of MD5.''')
parser.add_argument('-l','--keylen', default=16, type=int, help='''The length of the key
		    to be produced in bytes. For AES-128, this should be 16.''')
parser.add_argument('input_file', help='''A path to a traditional wordlist, such as you
		    would feed to a hash cracking utility.''')
parser.add_argument('output_file', default='keylist.txt', help='''The path, complete
		    with filename, to output the key list to.''')

args = parser.parse_args()

if not (args.nullpad or args.repeat or args.md5):
   print('[!] You must use one or more of --nullpad, --repeat, or --md5. Exiting.')
   exit(1)

try:
   wordlist = open(args.input_file,'r')
except:
   print('[!] Could not open file ' + args.input_file + '. Did you enter the path correctly?')
   exit(1)

try:
   out_fh = open(args.output_file,'w')
except:
   print('[!] Could not open file ' + args.output_file + ' for writing. Did you enter the path correctly?')
   exit(1)

#===========
# Functions
#===========

def derive_null_pad(password, keylen):
   pw_len = len(password)
   if pw_len >= keylen:
      return password[:keylen]
   else:
      return password + ('\x00' * (keylen-pw_len))

def derive_repeat(password, keylen):
   pw_len = len(password)
   # repeat password until 16 chars are filled
   return ''.join([password[i % pw_len] for i in range(keylen)])
      
def derive_md5(password, keylen):
   if keylen > 16:
      print('[!] Key length is too large for md5 to fill. Choose a smaller key length or do not use md5 key derivation.')
      exit(1)
   return md5(password).digest()[:keylen]

#======
# Main
#======   

for word in wordlist:
   word = word.rstrip()
   if word == '':
      continue
   if args.nullpad:
      out_fh.write( hexlify( derive_null_pad(word, args.keylen) ) + '\n')
   if args.repeat:
      out_fh.write( hexlify( derive_repeat(word, args.keylen) ) + '\n')
   if args.md5:
      out_fh.write( hexlify( derive_md5(word, args.keylen) ) + '\n')

