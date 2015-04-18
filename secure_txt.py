#Secure messages with XOR encryption and interleave
#Python 3.2 and onwards only.
#OZ1LQO

# Rev. 0.1  2015.02.20 First functional demo code
# Rev. 1.0  2015.02.24 Minor edits, I now have a usable system
# Rev. 1.1  2015.02.25 Changed the seed routine
# Rev. 1.2  2015.02.26 Added functionality to generate and choose between several keyfiles. Added Hash of ciphertext for validation
# Rev. 1.3  2015.03.22 Minor Changes

#DISCLAIMER: This script is open source - you may use it, change it, and dristribute it freely.
#Use this at your own risk - I take NO responsibility of anything that
#might happen, any damage or loss of values, or personal harm in any way. 

"""
This script demonstrates encryption of a secret message using a key with the same
length as the actual message. 

The idea is to build a simple, safe, system which could be used on Air-Gap'd
computers with just a basic Python 3.x installation. No extra libraries are needed,
there are no system specific dependencies, and the code will withstand full disclosure and review.

The functionality is as follows:
1) Enter a message, max 500 characters
2) Fill up with random characters (based on the standard random) until a total of 500
3) Shuffle (interleave) the text to remove frequency content (using a known seed)
This also makes a plaintext attack much harder to perform and it ensures usage of the
ENTIRE key length
4) XOR Encrypt it with a urandom key of the same length
--and the reverse for decryption using the same seed and key


This demo script can be used as the base in a communications system,
to safely pass messages: The keys and seeds will have to be pre-distributed, literally
hand-to-hand, but thats a minor problem considering building, and trusting,
an online 'safe' system. The keys and interleave seeds are paired, thus not reusing
the same seed for multiple keys, and the reverse.

NOTE: Since the random generator is different between python 2.x and 3.x, the
interleave function will fail between the two versions.

One more thing: It's deliberate that I don't allow storing cleartext in files,
for the simple reason, that doing that compromises security and it forces the user to
actively think of how he handles clear text information

See the 'help' option for more information

"""

from os import urandom
import os
import random
import string
import pickle
import hashlib


def shuffle(text, SEED):
    """Shuffles (interleaves) the input text, using a certain seed"""
    
    myList = list(text)
    random.seed(SEED)
    random.shuffle(myList)

    return ''.join(myList)


def reorder(shufText, SEED):
    """Reorders the interleaved text, using a certain seed"""
    
    myList = list(shufText)
    
    Order = list(range(len(myList)))
    # Order is a list having the same number of items as myList,
    # where each position's value equals its index

    random.seed(SEED)
    random.shuffle(Order)
    # Order is now shuffled in the same order as myList;
    # so each position's value equals its original index

    originalList = [0]*len(myList)   # empty list, but the right length
    for index,originalIndex in enumerate(Order):
        originalList[originalIndex] = myList[index]
        # copy each item back to its original index

    return ''.join(originalList)


 
def genkey(length):
    """Generate a unique random key"""
    return urandom(length)
 
def xor_strings(s,t):
    """XOR the message and key string together. Return the ecrypted string"""
    return "".join(chr(ord(a)^b) for a,b in zip(s,t))
     

def random_letter():
    """Returns a random letter. To be used to fill up messages to 500 characters"""
    return random.choice(string.ascii_letters)

def genseeds(amount):
    """Generates a list with 20-character random strings to be used as interleave seed
    Defining a random seed this long will make very hard to recreate"""
    seed_list=[]
    for i in range(amount):
        seedstring=''
        for j in range(20):
            seedstring+=random_letter()
        seed_list.append(seedstring)
    return seed_list
    


def encrypt_message(message, seed, key, length):
    """Perfoms encryption and validation of the message.
    Returns a string with the encrypted message. Lots of commented
    lines, use them for debug purposes if you want"""

    #Fill the rest with random characters
    full_message=message
    message_length=len(full_message)

    if message_length<length:
        while message_length<length:
            full_message+=random_letter()
            message_length+=1

    #print('\nFull Message to be interleaved:\n', full_message)

    #Interleave the message
    full_message_shuffled = shuffle(full_message, seed)

    #print('\nInterleaved message to be encrypted:\n', full_message_shuffled)

    #encrypt and decrypt (for validation)
    cipherText = xor_strings(full_message_shuffled, key)
    #print('\ncipherText:\n', cipherText)
    decrypt=xor_strings(cipherText,key)
    #print('\ndecrypted:\n', decrypt)

    decrypt_reordered = reorder(decrypt, seed)
    #print('\nreordered:\n', decrypt_reordered)

    #verify that encryption worked
    if full_message == decrypt_reordered:
        print('\nEncryption OK, unit test passed (encrypted and decrypted text is a perfect match)')
        #Doing a sha512 Hash to confirm the validity of the ciphertext
        m=hashlib.sha512()
        b=bytes(cipherText, 'utf-8')
        m.update(b)
        print("\nSHA512 Hash of the encrypted message with added randoms: ",m.digest())
    else:
        print('\nEncryption not OK, unit test failed. Saved file will be useless.')

    #For test purposes
    #print(seed, key)
    
    return cipherText


def decrypt_message(cipherText, seed, key):
    """Perfoms decryption and validation of the message.
    Returns a string with the encrypted message"""

    #Doing a sha512 Hash to confirm the validity of the ciphertext
    m=hashlib.sha512()
    b=bytes(cipherText, 'utf-8')
    m.update(b)
    print("\nSHA512 Hash of the ciphertext: ",m.digest())
    decrypt_sel=str(input("\nDo you want to decrypt the message (Y/N)? "))
    if decrypt_sel.lower()=="y":
        decrypt=xor_strings(cipherText,key)
        #print('\ndecrypted:\n', decrypt)
        decrypt_reordered = reorder(decrypt, seed)
        print('\nDecrypted file:\n', decrypt_reordered)
    else:
        print('\nCipherfile not decrypted')

    
def gen_key_seed(number, length):
    """Generates an amount of keys and seeds
    Returns two lists with seeds and leys"""
    
    #Generate random generator seeds. Make them 7-digit, so they're hard to guess
    #seeds=random.sample(range(10000000,99999999),number) #generate seeds as large random numbers

    #New version with 20char random strings, making it even harder to guess
    seeds=genseeds(number)

    keys=[]
    for i in range(number):
        keys.append(urandom(length)) #generate encryption keys using urandom

    return seeds, keys
        

def welcome():
    """Greeting"""
    print("""Welcome to Secure Text version 1.3 
This script encrypts and decrypts short messages based on a predistributed keyset.

The script has been designed to not bail out at the most common errors, but it
might still crash if you do something weird (like loading a ciphertext as a keyfile,
or the opposite) 

Select "H" for instructions and more information""")

def selectoptions():
    """Main menu"""

    print("""\n\n You now have the following options:
    1) Generate and store a keyset (52 keys and interleave seeds).
    2) Select a key/seed from the keyset
    3) Enter a text to be encrypted to a file
    4) Decrypt a message from file
    5) Load Keyfile
    H) Help and instructions
    0) Exit the program""")

    usersel=""
    while usersel =="":
          usersel=input("\nEnter your choice: ")

    return usersel

def instructions():
    print("""--BASICS--
\nThis script does XOR encryption of a message using a key with the
same length as the actual message. In theory, if the random generator is sufficiently
random, the message will be indecryptable.
Using 'urandom' secures a much safer key, as the random generator is
based on system measurements ( it gathers environmental noise from
device drivers and other sources into an entropy pool. The generator
also keeps an estimate of the number of bits of noise in the entropy pool.
From this entropy pool random numbers are created).

The functionality is as follows:
1) Enter a message, max 500 characters
2) Fill up with random characters (based on the standard random) until a total of 500
3) Shuffle (interleave) the text to remove frequency content (using a known seed)
This also makes a plaintext attack much harder to perform
4) XOR Encrypt it with a 'urandom' key of the same length
--and the reverse for decryption using the same seed and key
Note, that when decrypting the message, the added random characters will be still be there.
The usable message is the plaintext until the random tail starts. It's advisable to end
the message with fx. 'nnnn' to indicate that this is in fact the end of the message.


This script can be used as the base in a secure communication system,
to safely pass messages: The keys and seeds will have to be pre-distributed, literally
hand-to-hand, but thats a minor problem considering building, and trusting,
an online 'safe' system. The keys and interleave seed are paired, thus not reusing
the same seed for multiple keys, and the reverse.
To make a real secure system, use an Air-Gap, ie. a PC with no internet connection. Transfer
the messages by USB drives or a CD. (or a classical 3.5" disk, in that way, you'll know
if it has been compromised, since it'll quickly fill up with junk, which you didn't put there!
And you can physically hear if it's being accessed)

NOTE: Since the random generator is different between python 2.x and 3.x, the
interleave function will fail between the two versions.  """)
          
    input("\nPress ENTER to see the different options")

    print("""--OPTIONS--
    \nThe program gives you the following options:
    1) Generate and store a keyset
    52 keys, one for each week throughout the year. This can easily be changed by editing the
    key_amount variable.
    BE AWARE: If you overwrite a previously stored keyfile, it is impossible to recover it.
    
    2) Select a key
    Select a key, and the corresponding interleave seed
    
    3) Enter a message to be encrypted to a file
    Type in a text, max 500 characters (can easily be changed by setting the 'length' variable)
    Note, that if you change the message length, you need to generate new keyfiles
    Once encrypted, the message gets saved in a file, named by your choice.
    The routine calculates an SHA2-512 hash, to be used to confirm the validity of the ciphertext
    The hash is NOT included in the ciphertext and will have to transferred separately (or parts of it, see below)
    
    4) Decrypt a message from file
    Select a file to be decrypted. Remember to select the right key first
    The routine calculates an SHA2-512 hash of the ciphertext, to confirm the validity of the
    message before decrypting

    5) Load and activate a previously generated keyfile.
    
    H) Help and instructions
    This page
    
    0) Exit the program
    """)

    input("\nPress ENTER to continue to a short talk on encryption (and a disclaimer)")

    print("""--About encryption and the use of this script--
    \nDISCLAIMER: This script is open source - you may use it, change it, and dristribute it freely.
    Use this at your own risk - I take NO responsibility of anything that
    might happen, damage or personal harm in any way. Ok, I've said it, lets go on to the
    funny part.

    One of the crucial parts of encryption, is, how to distribute the key. In order to make this easy,
    and have it work across online media, systems like PGP has been developed. These systems are quite
    complicated, making it difficult to appreciate the security, simply because it's beyond most of us
    to debug and review the code - that is, if it's even available.
    
    My idea with this script is to make it easy to encrypt/decrypt short messages, enabling them to be
    transmitted over any chosen digital media.

    Instead of designing a complicated system as mentioned above, I decided to simply have the users
    share the keys physically, literally by exchanging a USB drive, a CD or even an old fashioned disc.
    The script supports a set of 52 keys, one for each week over the year.
    This can, of course, be changed to satisfy any needs (ie. a true One-Time-Pad)
    The length of the message has been set to 500 characters.

    So how does the encryption work: It's a classical XOR, *BUT*, the key has the same length at the actual
    message! This makes it extremely hard to decrypt. The key is generated by the 'urandom' function,
    which is a random generator designed for encryption purposes. The safety of the enryption relies
    largely on this random generator, so it comes down to the chosen OS' encryption module.
    One option could be simply replacing it with another, maybe real data from a nuclear-decay
    generator, would provide better encryption strength. (The urandom is generally concidered very safe..)
    In the meantime, I added some more functionality to increase security: 1) No matter how long the actual
    message is, I add random letters until I reach the desired total length (500). After that, I interleave
    ('shuffle') the message using the the native random generator in Python, with a preselected seed, which
    is paired with the used key, and distributed along with it in the key file. This way, different interleave
    seeds are used with different keys.
    The seed is a string with 20 random characters in it. (used to be a number between 10.000.000 and 99.999.999).
    This makes makes it very difficult to guess.
    Interleaving, takes away the frequency content and now I have 500 'pseudorandom' characters,
    which I XOR with the secure random sequence and store it in a file.
    This is the cipherfile I pass onto the recipient.
    Another nice feature of interleaving is, that it brings the ENTIRE key into play, you can't just decrypt parts
    of the message. Effectively, with a message length of 500 characters, this means that the key
    is 500x8=4000 bits, which could be increased by simply increasing the message length.""")

    input("\nPress ENTER to continue")

    print("""How safe is this? Pretty safe! It will take quite an effort to decrypt. As a test, I tried to 7zip
    one of the encrypted files: The original text is 500 bytes. 'Pickled' into a file by Python, it ended up
    counting 763bytes. The zipped version was 767bytes!
    It's a simple test, but it shows, that the message has been well randomized.
    I also tried to test the cipherfile with 'ENT' (a tool to test random generators, http://www.fourmilab.ch/random/).
    The entropy test came out at 6.5bits (8bits entirely random), the PI test landed at 3.0 (ideally 3.14)
    and the chi-square test failed, revealing the pickled file isn't random, which is understandable:
    'pickle' has its own formatting procedure, but still, it's getting close!

    As an experiment, I added an SHA2-512 calculation of the ciphertext, so it can be validated before
    decryption. SHA2-512 is concidered very safe, but I don't really know if this will compromise security.
    Use it at your own risk, If anything, use only parts of the checksum.
    (SHA2 was invented by NSA...).

    One last thing: Creating several keyfiles in a row might exhaust the urandom entropy pool, thus creating
    less secure keys. I don't know when this happens, so be aware. If you need several keyfiles, generate
    them on different computers/OS/platforms, with some ontime division, ie. leave the computer on over the
    night to regain entropy, before creating the next keyset""")
     

    input("\nPress ENTER to resume")

    
   
    
def main():
    """Main function"""

       
    welcome()
    
    length=500  #Message and key length
    key_amount=52 #Number of keys to be generated

    ##aa=genseeds(key_amount)
    ##print(aa,len(aa))
    
    seeds=[] #Initializing variables
    keys=[]
    seed=[]
    key=[]

    #Load keys if already present in the demo_keys.dat file
    try:
        f=open("demo_keys.dat","rb")
    except:
        print("\n--Keyfile not found, generate keys or load keyfile")
    else:
        seeds=pickle.load(f)
        keys=pickle.load(f)
        f.close()
        print("\nDemo key file loaded, use it for demonstration purposes only, consider it compromised..!")

    #print(seeds)

    choice=""

    while choice!="0":

        choice=selectoptions()
        
        if choice=="1": #generate 52 keys and seeds, store them to a file
            seeds, keys = gen_key_seed(key_amount, length)
            print(len(seeds)," seeds generated, ",len(keys)," keys generated")
            print("Directory list:\n")
            print(os.listdir(path='.'))
            filename=input("\nEnter a file name, eg. xxxx.dat: ")
            f = open(filename, "wb")
            pickle.dump(seeds, f)
            pickle.dump(keys, f)
            f.close
            print(filename," keyfile stored and activated")
            
            

        elif choice=="2": #select a key/seed set
            if len(seeds)==0:
                print("Generate or load keys first")
            else:
                keynumber=int(input("\nEnter a key number, 1-52: "))-1
                seed=seeds[keynumber]
                key=keys[keynumber]
                print("Key ",keynumber+1," selected")
            

        elif choice=="3": #Enter and encrypt a message. Store it in a file
            if seed==[]:
                print("Select Key first")
            else:
                print("Enter your message, max ",length," characters")
                message=input("->:")
                print('\nMessage:\n', message)
                cipher=encrypt_message(message, seed, key, length)
                print("Directory list:\n")
                print(os.listdir(path='.'))
                filename=input("\nEnter a file name, eg. xxxx.dat: ")
                f = open(filename, "wb")
                pickle.dump(cipher, f)
                f.close
                

        elif choice=="4": #Decrypt a cipher file
            print("Directory list:\n")
            print(os.listdir(path='.'))
            filename=''
            while filename=='':
                filename=input("Enter the desired file: ")
            try:
                f=open(filename,"rb")
            except:
                print("\n--Cipherfile not found--")
            else:
                if seed==[]:
                    print("Select Key first")
                else:
                    cipher=pickle.load(f)
                    f.close()
                    print("Cipherfile loaded..")
                    decrypt_message(cipher, seed, key)
                    

        elif choice=='5': #Load a keyset
            print("Directory list:\n")
            print(os.listdir(path='.'))
            filename=''
            while filename=='':
                filename=input("Enter the desired Key file: ")
            try:
                f=open(filename,"rb")
            except:
                print("\n--Keyfile not found..")
            else:
                seeds=pickle.load(f)
                keys=pickle.load(f)
                f.close()
                print("\nKey file loaded")
            
            

        
        elif choice.lower()=="h": #Show help text
            instructions()
                      

        else:
            return
        
   


main()







