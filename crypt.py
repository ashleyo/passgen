# Takes a body of text and deterministically hashes
# to produce a password

from contextlib import contextmanager
import hashlib

''' 
Characters that might be undesirable in passwords, 
filtered out unless fn=False is passed in
''' 
donotuse='"l\'1O' # characters that might be undesirable in passwords

@contextmanager
def opened(filename, mode="rb"):
    try:
        f = open(filename, mode)
    except IOError as err:
        yield None, err
    else:    
        try:
            yield f, None
        finally:
            f.close()

def passgen(fn='key.txt', n=20, flt=True, cycles=2009):
    '''
        Returns as a string a password based upon a key text and a 'pin'.
        The algorithm is deterministic and guaranteed to always produce the same password 
        with the same parameters and can therefore be used to recover a forgotten password
        Keyword parameters are fn, n, flt, cycles all of which have default values.
        
        fn - the name/path of the file to be used. Intended to be a text file but it is read 
        in binary mode so any file could be used. Should not be too large, it is read in a single 
        operation into memory. 2k - 1M would be a sensible range. Default 'key.txt'. Obviously the default
        should only be used for testing. Ideally the text would not be stored on the same system but be 
        wary of web sources as they might change without warning. 

        n - number of characters in the returned password. Default and max is 20. 
        For password recovery the number of characters must be known! Leave at default unless the target 
        authentication system does not allow 20.

        flt - whether characters that might be confusing in passwords " ' 1 l O should be filtered out.
        Defaults to True. Since the password might or might not contain any of these characters before 
        filtering, changing this parameter is not guaranteed to change the generated password.

        cycles - allows a numeric 'pin' to be provided to further perturb the password generation as
        useful additional security in an environment where the key text might be easily identified. 
        For password recovery the pin used must be remembered! A good source might be the first 3-4 digits
        of the serial number of some physical object.
    '''
    m = hashlib.sha512()
    with opened(fn) as (f,err):
        if err:
            print('Key file could not be opened:', err)
            exit(-1)
        else:
            m.update(f.read())
    for i in range(cycles):
        m.update(m.digest())
    bb = m.digest()
    s=""
    for b in bb:
        val = int(b & 0x7f)
        if not (32 < val < 127): continue
        s = s + chr(val)
    if flt:
        s = s.translate({ord(c): None for c in donotuse})
    return s if len(s) <= n else s[:n]

if __name__=='__main__':
    print(passgen())
