import socket, hashlib                               
import nacl, binascii
from Cryptodome.Cipher import AES
from nacl.public import PrivateKey, Box
from ecdsa import SigningKey, NIST192p, VerifyingKey

#creates public and private keys using Curve25519
def ecc():
    privatekey = PrivateKey.generate()
    publickey = privatekey.public_key
    return privatekey, publickey

priv, pub = ecc()
pub_server = str(pub)

#creates a shared secret key
def ecc_diffie_hellman(other_key):
    other_key = nacl.public.PublicKey(other_key)
    server_box = Box(priv, other_key)
    s_k = server_box.shared_key()
    return s_k

# create a socket object
serversocket = socket.socket(
	        socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 19999                                           

# bind to the port
serversocket.bind((host, port))                                  

# queue up to 5 requests
serversocket.listen(5)                                           

while True:
    # establish a connection
    clientsocket,addr = serversocket.accept()      

    print("Connected to the client %s" % str(addr))
    
    clientsocket.send(pub_server)    #send
    
    pub_client = clientsocket.recv(1024)  #recv
    shared_key = ecc_diffie_hellman(pub_client)
    sh_hashed = hashlib.sha256(shared_key).hexdigest()
 
    
    print "This is the hash for the server's public key: " + hashlib.sha256(pub_server).hexdigest()
    print "This is the hash for the shared secret: " + sh_hashed
    
    #signing key
    priv_signature = SigningKey.generate(curve=NIST192p) 
    #verifying key
    pub_signature = priv_signature.get_verifying_key()
    
    #converting verifying to a string for transmission over the network
    pub_signature_str = pub_signature.to_string()
    #pub_sign_server = SigningKey.from_string(pub_signature_str, curve=NIST192p)

    #send the verifying key
    clientsocket.send(pub_signature_str)     
    
    signature = priv_signature.sign(sh_hashed)
    
    #send the digital sign
    clientsocket.send(signature)
    
    #receive the verifying key from client
    veri_key_client_str = clientsocket.recv(1024)
    veri_key_client = VerifyingKey.from_string(veri_key_client_str, curve=NIST192p)
    
    #receive digital sign from client
    dig_sign_client = clientsocket.recv(1024)
    
    if veri_key_client.verify(dig_sign_client, sh_hashed):
        print "Verified succesfully"
        assert veri_key_client.verify(dig_sign_client, sh_hashed)
    else:
        clientsocket.close()
    
        
    plaintext = "And you run and you run to catch up with the sun but it's sinking \nRacing around to come up behind you again \nThe sun is the same in a relative way, but you're older \nShorter of breath and one day closer to death"
    hexplain = binascii.hexlify(plaintext)
    
    nonce_ = "darksideofdamoon"
    
    #encrypt with AES in GCM mode using the package Cryptodome
    cipher = AES.new(shared_key, AES.MODE_GCM, nonce_)
    etext = cipher.encrypt(hexplain)

    #send the encrypted text
    clientsocket.send(etext)
    
    print("Enter the text that you wish to send to the client: ")
    custom_message = raw_input()
    hexplain_custom = binascii.hexlify(custom_message)
    
    #encrypt with AES in GCM mode using the package Cryptodome
    cipher_custom = AES.new(shared_key, AES.MODE_GCM, "qwertyuiopasdfgh")
    etext_custom = cipher_custom.encrypt(hexplain_custom)

    #send the encrypted text
    clientsocket.send(etext_custom)
    clientsocket.close()