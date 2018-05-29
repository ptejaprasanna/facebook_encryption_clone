import socket, binascii, nacl, hashlib
from nacl.public import PrivateKey, Box
from ecdsa import SigningKey, NIST192p, VerifyingKey
from Cryptodome.Cipher import AES

def ecc():
    privatekey = PrivateKey.generate()
    publickey = privatekey.public_key
    return privatekey, publickey

priv, pub = ecc()
pub_client = str(pub)

#creates a shared secret key
def ecc_diffie_hellman(other_key):
    other_key = nacl.public.PublicKey(other_key)
    server_box = Box(priv, other_key)
    s_k = server_box.shared_key()
    return s_k

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 19999

# connection to hostname on the port.
s.connect((host, port))                               

# Receive public key from the server
pub_server = s.recv(1024)                   #recv

# send the public key to the server
s.send(pub_client)     
#create a shared secret
shared_key = ecc_diffie_hellman(pub_server)

#hash the shared the shared secret
sh_hashed = hashlib.sha256(shared_key).hexdigest()

print "This is the hash for the client's public key: " + hashlib.sha256(pub_client).hexdigest()
print "Hash for the shared secret: " + sh_hashed

#receive teh verifying key
pub_sign_server_str = s.recv(1024)
pub_sign_server = VerifyingKey.from_string(pub_sign_server_str, curve=NIST192p)

#receive message sign
v_message = s.recv(1024)

if pub_sign_server.verify(v_message, sh_hashed):
    print "Verified succesfully"
    assert pub_sign_server.verify(v_message, sh_hashed)
else:
    s.close()


#signing key
priv_signature = SigningKey.generate(curve=NIST192p) 
#verifying key
pub_signature = priv_signature.get_verifying_key()

#converting verifying to a string for transmission over the network
pub_signature_str = pub_signature.to_string()
#pub_sign_server = SigningKey.from_string(pub_signature_str, curve=NIST192p)

#send the verifying key
s.send(pub_signature_str)     

signature = priv_signature.sign(sh_hashed)

#send the digital sign
s.send(signature)

#receive ciphertext
etext = s.recv(1024)
nonce_ = "darksideofdamoon"
cipher = AES.new(shared_key, AES.MODE_GCM, nonce_)
hexplain = cipher.decrypt(etext)

print "The decrypted text is: " + binascii.unhexlify(hexplain)

#receive ciphertext
etext_custom = s.recv(1024)
cipher_custom = AES.new(shared_key, AES.MODE_GCM, "qwertyuiopasdfgh")
hexplain_custom = cipher_custom.decrypt(etext_custom)

print "The decrypted text is: " + binascii.unhexlify(hexplain_custom)
s.close()
