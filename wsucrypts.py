# Name: Harpreet Singh
# Class: CS 427
# Date: 03/03/2020
# Program-Name: WSU-Crypt
# 
# This program uses block-encryption algorithm based on Twofish and Skipjack that 
# uses using a 64 bit block size and a 64 bit key. 
# We have a 2 input files: 
# 	standard ASCII text file(plaintext.txt)
# 	randomly chosen secret key(key.txt)
# and make 1 Output file: 
# 	HEX text file (call the file cyphertext.txt) which is the encryption of the input file

# It should also decrypt. 
from os import path
from time import time

# To see extra info
DebugMode = True
VerboseMode = True

# Public function used for both encrypting and decrypting 

# Input and Output files
plain_text = "plaintext.txt"
key_text = "key.txt"

cipher_text = "cyphertext.txt"

#To keep track of the differt Keys 
KeyValue = 0

# To either encrypt or decrypt 
EncryptionMode = True

#======================== Functions for Encryption and Decryption ===========

# Help convert to hex for last bit
def hexstring2hex(text, type = 16):
    value = int(text, type)  
    return value

# This function fetch the key from encryption from key.txt
def getKey():
    global KeyValue 
    with open(key_text) as f:
        encryptionKey = f.read()
        if DebugMode: print("encryptionKey:", encryptionKey)
    if encryptionKey[0] is not None and encryptionKey[0] == '0' and encryptionKey[1] is not None and encryptionKey[1] == 'x':
        if DebugMode: print("'0x' marker preceding key")
        KeyValue = hexstring2hex(encryptionKey, 0)
    else:
        if DebugMode: print("no hex marker preceding key")
        KeyValue = hexstring2hex(encryptionKey)

# This will output dependint on encrytion mode is on, it will output encryted text else decrypted text
def writeOutput(results):
    direction = ""
    filename = ""
    if EncryptionMode: 
        direction = "Encrypted Ciphertext"
        filename = cipher_text
        with open(filename, "w") as f:
            f.write('{:016x}'.format(results))
    else: 
        direction = "Decrypted Plaintext"
        filename = plain_text
        with open(filename, "w") as f:
            f.write(results)
    print("Writing", direction, "to", filename)
    print("\n=========== Done ==============\n")

# Concatenates two hexadecimal values
def concatHex(a, b, bit = 8):
    return a << bit | b

# Takes a 64 bit hex value and returns four 16 bit sections.
def hex64ToHex16(valueHex):
    a3 = valueHex & 0xffff
    a2 = (valueHex >> 16) & 0xffff
    a1 = (valueHex >> 32) & 0xffff
    a0 = (valueHex >> 48) & 0xffff
    return (a0, a1, a2, a3)

#======================== Function for Encryption ========================

#This function is used for adding extra padding to given string
def padding(numberOfPadding, stringChunk):
    for i in range(numberOfPadding):
        stringChunk += '0'
    return stringChunk

#This function breaks the string into chunks
def plaintext2Chunk(plaintext_str, bit=8):
    arrayOfChunks = []
    lengthOfPlaintText = len(plaintext_str)
    for i in range(0, lengthOfPlaintText, bit):
        if (i+bit <= lengthOfPlaintText):
            arrayOfChunks.append(plaintext_str[i : i+bit])
        else:
            countOfLeftOver = lengthOfPlaintText - i
            leftOver = plaintext_str[i : lengthOfPlaintText]
            arrayOfChunks.append(padding(bit-countOfLeftOver, leftOver))
    return arrayOfChunks

#This function converts the string value to hexadecimal value
def convertString2Hex(string):
    value = 0
    for i in string:
        value = value << 8 | ord(i)
    return value

#This function breaks string to hexadecimal blocks (array) and return it
def convertString2HexBlocks(string_array):
    arrayOfHex = []
    for chunk in string_array:
        valueOfHex = convertString2Hex(chunk)
        arrayOfHex.append(valueOfHex)
    return arrayOfHex

#This function generates 64 bit hexadecimal blocks from the plain text in plaintext.txt
def convertPlaintext2HexBlock():
    with open(plain_text) as f:
        textInput = f.read()
    if VerboseMode: print("Plaintext input:", textInput)
    blocks = plaintext2Chunk(textInput)
    if DebugMode: print("plaintext blocks:", blocks)
    blocksOfHex = convertString2HexBlocks(blocks)
    if DebugMode: print("blocksOfHexaDecimals from plaintext:", blocksOfHex)
    return blocksOfHex

#======================== Functin for Decryption  ==========================

#This function takes a cypher text and converts to chunks
def convertCipher2Chunk():
    with open(cipher_text) as f:
        cipherInput = f.read()
    if VerboseMode: print("raw Ciphertext input:", cipherInput)    
    if cipherInput[0] is not None and cipherInput[0] == '0' and cipherInput[1] is not None and cipherInput[1] == 'x':
        cipherInput = cipherInput[2:]
        if DebugMode: print("'0x' marker preceding ciphertext input")
    if DebugMode: print(cipherInput)
    arrayOfCipherChunks = plaintext2Chunk(cipherInput, 16)
    arrayOfHexCipherChunks = []
    for chunk in arrayOfCipherChunks:
        hex_chunk = hexstring2hex(chunk)
        arrayOfHexCipherChunks.append(hex_chunk)
    if DebugMode: print("ciphertext hex chunks:", arrayOfHexCipherChunks)
    return arrayOfHexCipherChunks

#This function converts given hexadecimal to string
def convertHex2Sting(hex):
    plaintext = ''
    for i in range(7, -1, -1):
        b = hex >> (8*i) & 0xff
        if(chr(b) != '0'):
            plaintext = plaintext + chr(b)
    return plaintext


#======================== Subroutines from PDF =========================

# SKIPJACK F-table is in hexadecimal. The high order 4 bits of input index the row and the
# low order 4 bits index the column.
f_table = [0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9, 0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28, 0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8, 0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90, 0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76, 0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d, 0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18, 0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4, 0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40, 0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5, 0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2, 0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8, 0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac, 0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46]

#Input number x and it is assumed that K() has access to the current, stored, 64 bit key
# These functions are the Key Schdule
MaskValue = (1 << 64) - 1
def left_rotate_key():
    key = ((KeyValue << 1) & MaskValue)| KeyValue >> 64-1
    return key
    
def right_rotate_key():
    key = KeyValue >> 1| ((KeyValue << 64-1) & MaskValue)
    return key


def K(x):
    global KeyValue
    chunk = x%8
    if EncryptionMode:  # Encrypting
        KeyValue = left_rotate_key()
        segment = KeyValue >> (chunk * 8) & 0xff
        return segment
    else:  # Decrypting
        segment = KeyValue >> (chunk * 8) & 0xff
        KeyValue = right_rotate_key()
        return segment

# This is function exactly given in project pdf for getting conactenated hexes
# The Input is 16 bits, w and the round number (and maybe the subkeys). A fixed table called, the
# F-table, is used to perform a substitution (see last page).
def G(w, key1, key2, key3, key4):
    if DebugMode: print("w:", hex(w))
    g1 = (w >> 8) & 0xff
    g2 = w & 0xff
    g3 = f_table[g2 ^ key1] ^ g1
    g4 = f_table[g3 ^ key2] ^ g2
    g5 = f_table[g4 ^ key3] ^ g3
    g6 = f_table[g5 ^ key4] ^ g4
    return concatHex(g5, g6)

#This function is used for decryption
def F(R0, R1, round):
    key_list = []
    if EncryptionMode:
        start = 0; end = 12; step = 1
    else:
        start = 11; end = -1; step = -1
    for i in range(start, end, step):
        key_list.append(K(4*round+i%4))
    if DebugMode: print("key list:", key_list)
    if EncryptionMode == False:
        key_list = list(reversed(key_list))
    T0 = G(R0, key_list[0], key_list[1], key_list[2], key_list[3])
    T1 = G(R1, key_list[4], key_list[5], key_list[6], key_list[7])
    F0 = (T0 + 2 * T1 + concatHex(key_list[8], key_list[9])) % 2**16
    F1 = (2 * T0 + T1 + concatHex(key_list[10], key_list[11])) % 2**16
    if VerboseMode: print("t0:", hex(T0), "t1:", hex(T1))
    if VerboseMode: print("f0:", hex(F0), "f1:", hex(F1))
    return (F0, F1)

 #This function will take whitening, and give rounds
def takeWhitening(w0, w1, w2, w3):
    K0,K1,K2,K3 = hex64ToHex16(KeyValue)
    R0 = w0 ^ K0
    R1 = w1 ^ K1
    R2 = w2 ^ K2
    R3 = w3 ^ K3
    return (R0, R1, R2, R3)

#This function will get the whitening
def getWhitening(y0, y1, y2, y3):
    K0,K1,K2,K3 = hex64ToHex16(KeyValue)
    C0 = y0 ^ K0
    C1 = y1 ^ K1
    C2 = y2 ^ K2
    C3 = y3 ^ K3
    return (C0, C1, C2, C3)

# This function will take hexadecimal string and convert to quarters
def convertToQuarters(text): 
    # We declare four whitening variables w0,w1,w2,w3
    w0, w1, w2, w3 = hex64ToHex16(text)
    # Show values of variables if debug mode is on.
    if DebugMode: print("w0:", hex(w0))
    if DebugMode: print("w1:", hex(w1))
    if DebugMode: print("w2:", hex(w2))
    if DebugMode: print("w3:", hex(w3))
    # Create Round
    R0, R1, R2, R3 = takeWhitening(w0, w1, w2, w3)
    # Check if encryptionMode is on
    if EncryptionMode:
        start = 0; end = 16; step = 1
    else:
        start = 15; end = -1; step = -1
    round = 0
    for i in range(start, end, step):
        if DebugMode: print("on the i'th step of convertToQuarters:", i)
        if VerboseMode: print("Beginning of Round: " + str(round))
        F0, F1 = F(R0, R1, i)
        newR0 = R2 ^ F0
        newR1 = R3 ^ F1
        R2 = R0
        R3 = R1
        R0 = newR0
        R1 = newR1
        if VerboseMode: print("End of Round: " + str(round) + "\n")
        round += 1
    y0 = R2
    y1 = R3
    y2 = R0
    y3 = R1
    # Cryptography Action
    C0, C1, C2, C3 = getWhitening(y0, y1, y2, y3)
    quarterCrypt = (C0 << 48) | (C1 << 32) | (C2 << 16) | (C3)
    return quarterCrypt

#====================   Encryption and Decryption ========================================

def en(): 
    print("\n========= Encrypting =========\n")
    blocksOfHex = convertPlaintext2HexBlock()
    getKey()
    if DebugMode: print("key:", hex(KeyValue))
    hexCypher = 0
    for block in blocksOfHex:
        hexCypher = concatHex(hexCypher, convertToQuarters(block), 64)
    if DebugMode: print("Ciphertext:", hex(hexCypher))    
    writeOutput(hexCypher)


def de():
    print("\n=========== Decrypting ============== \n")
    global EncryptionMode 
    EncryptionMode = False
    getKey()
    arrayOfCipherChunks = convertCipher2Chunk()
    if DebugMode: print(arrayOfCipherChunks)
    plaintext = ""
    for chunk in arrayOfCipherChunks:
        if DebugMode: print("chunk:", hex(chunk))
        if DebugMode: print("chunk int:", chunk)
        decrypted_chunk = convertToQuarters(chunk)
        if DebugMode: print(hex(decrypted_chunk))
        plaintext += convertHex2Sting(decrypted_chunk)
        if DebugMode: print("plaintext:", plaintext)
    writeOutput(plaintext)    

#========================  Main function  =============================== 
if __name__ == '__main__': 
    print ("=========Welcome to the WSU-Crypt program===============\n")
    print ("You can either encrypt by pressing 'e' or decrypt by pressing 'd'\n")
    crypt = input("Encrypting or decrypting [e/d]: \n")

    #Check to see what the user puts in
    if crypt == 'e':
        en()
    elif crypt == 'd':
        de()
    else: 
        print("Invalid Entry!!! Exiting..... Please try again later\n")

