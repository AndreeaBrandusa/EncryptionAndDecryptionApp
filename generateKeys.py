from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def desKey():
    key = get_random_bytes(8)

    with open("keys/desKey.key", "wb+") as file:
        file.write(key)

def aesKey():
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    with open("keys/aesKey.key", "wb+") as file:
        file.write(iv + key)
        

def rsaKey():
    key = RSA.generate(2048)

    public_key = key.publickey()
    private_key = key

    with open("keys/rsaKey.key", "wb+") as file, open("keys/rsapKey.key", "wb+") as pfile:
        file.write(public_key.exportKey("DER"))
        pfile.write(private_key.exportKey("DER"))


if __name__ == '__main__':
    desKey()
    aesKey()
    rsaKey()