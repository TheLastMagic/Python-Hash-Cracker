import hashlib

print("""                            [!]Options
            _____These_work____________      ________These_work_______________
            1.MD5 Password/Hash Cracker      11.SHA3_224 Password/Hash Cracker
            2.SHA512 Password/Hash Cracker   12.SHA3_256 Password/Hash Cracker
            3.SHA256 Password/Hash Cracker   13.SHA3_384 Password/Hash Cracker
            4.SHA1 Password/Hash Cracker     14.SHA3_512 Password/Hash Cracker
            5.SHA224 Password/Hash Cracker
            6.SHA384 Password/Hash Cracker
            7.Blake2b Password/Hash Cracker
            8.Blake2s Password/Hash Cracker
            9.Shake_128 Password/Hash Cracker
            10.Shake_256 Password/Hash Cracker
            
            """)

options = input("[?] Select Option: ")

md5_flag = 0
sha512_flag = 0
sha256_flag = 0
sha1_flag = 0
sha224_flag = 0
sha384_flag = 0
blake2b_flag = 0
blake2s_flag = 0
shake128_flag = 0
shake256_flag = 0
sha3_224_flag = 0
sha3_256_flag = 0
sha3_384_flag = 0
sha3_512_flag = 0


if options == "1":
    md5_pass_hash = input("[?] Enter MD5 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        md5_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for md5_word in md5_pass_file:
        md5_enc_wrd = md5_word.encode('utf-8')
        md5_digest = hashlib.md5(md5_enc_wrd.strip()).hexdigest()

        if md5_digest == md5_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + md5_word)
            md5_flag = 1
            break

    if md5_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "2":
    sha512_pass_hash = input("[?] Enter SHA512 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha512_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha512_word in sha512_pass_file:
        sha512_enc_wrd = sha512_word.encode('utf-8')
        sha512_digest = hashlib.sha512(sha512_enc_wrd.strip()).hexdigest()

        if sha512_digest == sha512_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha512_word)
            sha512_flag = 1
            break

    if sha512_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "3":
    sha256_pass_hash = input("[?] Enter SHA256 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha256_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha256_word in sha256_pass_file:
        sha256_enc_wrd = sha256_word.encode('utf-8')
        sha256_digest = hashlib.sha256(sha256_enc_wrd.strip()).hexdigest()

        if sha256_digest == sha256_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha256_word)
            sha256_flag = 1
            break

    if sha256_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "4":
    sha1_pass_hash = input("[?] Enter SHA1 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha1_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha1_word in sha1_pass_file:
        sha1_enc_wrd = sha1_word.encode('utf-8')
        sha1_digest = hashlib.sha1(sha1_enc_wrd.strip()).hexdigest()

        if sha1_digest == sha1_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha1_word)
            sha1_flag = 1
            break

    if sha1_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "5":
    sha224_pass_hash = input("[?] Enter SHA224 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha224_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha224_word in sha224_pass_file:
        sha224_enc_wrd = sha224_word.encode('utf-8')
        sha224_digest = hashlib.sha224(sha224_enc_wrd.strip()).hexdigest()

        if sha224_digest == sha224_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha224_word)
            sha224_flag = 1
            break

    if sha224_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "6":
        sha384_pass_hash = input("[?] Enter SHA384 hash: ")
        wordlist = input("[?] Enter passlist: ")

        try:
            sha384_pass_file = open(wordlist, "r")
        except:
            print("[-] 404 File Not Found")
            quit()

        for sha384_word in sha384_pass_file:
            sha384_enc_wrd = sha384_word.encode('utf-8')
            sha384_digest = hashlib.sha384(sha384_enc_wrd.strip()).hexdigest()

            if sha384_digest == sha384_pass_hash:
                print("[+] Password Found")
                print("[+] Password is " + sha384_word)
                sha384_flag = 1
                break

        if sha384_flag == 0:
            print("[-] Password/Passphrase is not in passlist")

elif options == "7":
    blake2b_pass_hash = input("[?] Enter Blake2b hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        blake2b_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for blake2b_word in blake2b_pass_file:
        blake2b_enc_wrd = blake2b_word.encode('utf-8')
        blake2b_digest = hashlib.blake2b(blake2b_enc_wrd.strip()).hexdigest()

        if blake2b_digest == blake2b_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + blake2b_word)
            blake2b_flag = 1
            break
    
    if blake2b_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "8":
        blake2s_pass_hash = input("[?] Enter Blake2s hash: ")
        wordlist = input("[?] Enter passlist: ")

        try:
            blake2s_pass_file = open(wordlist, "r")
        except:
            print("[-] 404 File Not Found")
            quit()

        for blake2s_word in blake2s_pass_file:
            blake2s_enc_wrd = blake2s_word.encode('utf-8')
            blake2s_digest = hashlib.blake2s(blake2s_enc_wrd.strip()).hexdigest()

            if blake2s_digest == blake2s_pass_hash:
                print("[+] Password Found")
                print("[+] Password is " + blake2s_word)
                blake2s_flag = 1
                break
        
        if blake2s_flag == 0:
            print("[-] Password/Passphrase is not in passlist")

elif options == "9":
    shake128_pass_hash = input("[?] Enter Shake128 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        shake128_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()
    
    for shake128_word in shake128_pass_file:
        shake128_enc_wrd = shake128_word.encode('utf-8')
        shake128_digest = hashlib.shake_128(shake128_enc_wrd.strip()).hexdigest()

        if shake128_digest == shake128_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + shake128_word)
            shake128_flag = 1
            break

    if shake128_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "10":
    shake256_pass_hash = input("[?] Enter Shake_256 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        shake256_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()
    
    for shake256_word in shake256_pass_file:
        shake256_enc_wrd = shake256_word.encode('utf-8')
        shake256_digest = hashlib.shake_256(shake256_enc_wrd.strip()).hexdigest()

        if shake256_digest == shake256_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + shake256_word)
            shake256_flag = 1
            break

    if shake256_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "11":
    sha_3_224_pass_hash = input("[?] Enter SHA3/224 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha_3_224_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha_3_224_word in sha_3_224_pass_file:
        sha_3_224_enc_wrd = sha_3_224_word.encode('utf-8')
        sha_3_224_digest = hashlib.sha3_224(sha_3_224_enc_wrd.strip()).hexdigest()

        if sha_3_224_digest == sha_3_224_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha_3_224_word)
            sha3_224_flag = 1
            break

    if sha3_224_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "12":
    sha_3_256_pass_hash = input("[?] Enter SHA3/256 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha_3_256_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha_3_256_word in sha_3_256_pass_file:
        sha_3_256_enc_wrd = sha_3_256_word.encode('utf-8')
        sha_3_256_digest = hashlib.sha3_224(sha_3_256_enc_wrd.strip()).hexdigest()

        if sha_3_256_digest == sha_3_256_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha_3_256_word)
            sha3_256_flag = 1
            break

    if sha3_256_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "13":
    sha_3_384_pass_hash = input("[?] Enter SHA3/384 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha_3_384_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha_3_384_word in sha_3_384_pass_file:
        sha_3_384_enc_wrd = sha_3_384_word.encode('utf-8')
        sha_3_384_digest = hashlib.sha3_224(sha_3_384_enc_wrd.strip()).hexdigest()

        if sha_3_384_digest == sha_3_384_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha_3_384_word)
            sha3_384_flag = 1
            break

    if sha3_384_flag == 0:
        print("[-] Password/Passphrase is not in passlist")

elif options == "13":
    sha_3_512_pass_hash = input("[?] Enter SHA3/512 hash: ")
    wordlist = input("[?] Enter passlist: ")

    try:
        sha_3_512_pass_file = open(wordlist, "r")
    except:
        print("[-] 404 File Not Found")
        quit()

    for sha_3_512_word in sha_3_512_pass_file:
        sha_3_512_enc_wrd = sha_3_512_word.encode('utf-8')
        sha_3_512_digest = hashlib.sha3_224(sha_3_512_enc_wrd.strip()).hexdigest()

        if sha_3_512_digest == sha_3_512_pass_hash:
            print("[+] Password Found")
            print("[+] Password is " + sha_3_512_word)
            sha3_512_flag = 1
            break

    if sha3_512_flag == 0:
        print("[-] Password/Passphrase is not in passlist")



blank = input()