from itertools import cycle


def xorcrypt(data:bytes, key:bytes)->bytes:
    # encrypt and decrypt bytes
    
    # Loop the key (abc become abcabcabcab....)
    infinite_key = cycle(key)
    # create couple from data and key.
    match = zip(data, infinite_key)
    # XOR key and data
    tmp = [a ^ b for a,b in match]
    # return encrypted or decrypted data
    return bytes(tmp)

def xorfile(filename:str, key:bytes)->bytes:
    # encrypt and decrypt file

    # load the file
    with open(filename, "rb") as f:
        plain = f.read()

    # Do the job
    encrypted = xorcrypt(plain, key)

    # write the result on the same file
    with open(filename, "wb") as f:
        f.write(encrypted)