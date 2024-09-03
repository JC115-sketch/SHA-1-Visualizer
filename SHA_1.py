import math


def sha1_padding(message):
    
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    # 8 bits in a byte...

    # hex = base 16 so 80 = 8 * 16^1 = 128 purpose --> mark end of original message
    # with one 'high' bit
    message += b'\x80'
    
    # making sure length of message is equal to 448 mod 512
    # padding with zeroes until message is 448 bits
    # keeps adding x00 bytes until message is 56 bytes (448 bits)
    # loop is working in bytes 55 % 64 is NOT 56, 56 is, exits loops
    while len(message) % 64 != 56:
        message += b'\x00'
        
    # append length of original message as a 64-bit (8 byte) big-endian integer
    # 512 - 448 = 64 bits (reserved for length of original message)
    message += original_bit_len.to_bytes(8, byteorder='big')
    
    return message


def sha1_blocks(message):
    
    blocks = []
    
    # splitting message into 512-bit blocks (64 bytes)
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        blocks.append(block)
        
    return blocks


def sha1_initialize_hash_values():
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    # each are the first 32 bits of fractional parts of sqr rt of first 8 prime numbers
    # ensures a unique starting point for the hashing
    
    return h0, h1, h2, h3, h4


def sha1_rot1(word, n):
    return ((word << n) | (word >> (32 - n))) & 0xffffffff
    # AND applied to any bit past len of 28, will be ANDed with a 0 and
    # will be discared per AND truth table
    # bitwise shifted right and left, OR applied to results


def sha1_ch(x, y, z):
    return (x & y) ^ (~x & z)


def sha1_maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sha1_compress(h0, h1, h2, h3, h4, w):
    print(f"\nStarting compression for calculated message schedule")

    # initialize working variables
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    
    for i in range(80):
        # debug
        if i >= len(w):
            print(f"Index error at i = {i}. Length of w = {len(w)}")
            break

        if 0 <= i <= 19:
            # introduce mixing and non-linearity
            f = sha1_ch(b, c, d)
            k = 0x5A827999
            
        elif 20 <= i <= 39:
            # ensures that at least two inputs agree (return true through AND operation)
            f = sha1_maj(b, c, d)
            k = 0x6ED9EBA1
        
        elif 40 <= i <= 59:
            # XOR for further mixing
            f = (b ^ c ^ d)
            k = 0x8F1BBCDC
            
        elif 60 <= i <= 79:
            f = sha1_maj(b, c, d)
            k = 0xCA62C1D6
            
        print(f"\nRound {i + 1} (k={k:08x}, f={f:08x}):")
        print(f" a = {a:08x}, b = {b:08x}, c = {c:08x}, d = {d:08x}, e = {e:08x}")
            
        temp = (sha1_rot1(a, 5) + f + e + k + w[i]) & 0xffffffff
        # rotate 'a' left by 5 bits, moves variables down the chain --> a becomes b etc.
        # moving the variables again introduces mixing and non-linearity for each round
        e = d
        d = c
        c = sha1_rot1(b, 30)
        b = a
        a = temp

    # adds working variables back into hash values
    # this ensures that each block's processing affects the final hash
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff
    # forces hash values to stay within 32 bit range
    
    print("\nFinal hash values after compression:")
    print(f"h0 = {h0:08x}, h1 = {h1:08x}, h2 = {h2:08x}, h3 = {h3:08x}, h4 = {h4:08x}")
    
    return h0, h1, h2, h3, h4


SHA1_ROUND_CONSTANTS = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]


def sha1_message_schedule(block):
    # expands initial 16 32 bit (4 byte) words into 80 words
    print(f"\nMessage schedule for block: {block.hex()}")

    w = [0] * 80
    
    for i in range(16):
        # each block is 64 bytes -- split into 16 words of 4 bytes each
        w[i] = int.from_bytes(block[i * 4:i * 4 + 4], byteorder='big')
        # converts each 4 byte segment into a 32-bit integer
        # from b'\x00\x01\x02\x03 --> w[0] = 0x00010203 w[1] = 0x04050607
        print(f"Initial word w[{i}]: {w[i]:08x}")
        
    for i in range(16, 80):
        w[i] = sha1_rot1(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
        # XOR and rotation function ensure that any change input affect all parts of the hash
        # XOR creates a new value from some iteration of original 16 words
        # words 16 - 79 are generated via XOR operation and the 1-bit left rotation
        # ensures that every word depends on multiple previous
        print(f"Computed word w[{i}]: {w[i]:08x}")
        
    print("\nFinal message schedule:")
    # formatting for print to terminal
    for i in range(80):
        if i % 8 == 0:
            # just prints a newline every clean factor of 8 in the loops progression
            print()
        print(f"w[{i}]: {w[i]:08x}", end=", ")

    return w


def sha1_hash(message):
    h0, h1, h2, h3, h4 = sha1_initialize_hash_values()
    padded_message = sha1_padding(message)
    blocks = sha1_blocks(padded_message)
    
    for block in blocks:
        w = sha1_message_schedule(block)
        h0, h1, h2, h3, h4 = sha1_compress(h0, h1, h2, h3, h4, w)
        
    digest = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}"
    print(digest)
    return digest


if __name__=='__main__':
    message = input("What message would you like to hash?: ")
    sha1_hash(message.encode('utf-8'))
    

