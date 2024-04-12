from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

import hashlib
import time
import json

class Blockchain:
    difficulty = '000' 

    def __init__(self,private_key,publickey):
        self.transactions = []
        self.chain = []
        self.private_key = private_key
        self.public_key = publickey
        genesis_block = {
            'index': 0,
            'timestamp': time.time(),
            'transactions': [],
            'nonce': 0,
            'previous_hash': '0',
            'signature':''
        }
        genesis_hash = self.compute_hash(genesis_block)
        genesis_block['nonce'] = self.proof_of_work(0, genesis_hash, [])
        self.chain.append(genesis_block)

    def sign_block(self,block):
        hash_block = SHA512.new(json.dumps(block).encode())
        signature = pkcs1_15.new(self.private_key).sign(hash_block)
        return signature

    

   

if __name__ == '__main__':
        
    key = RSA.generate(2048)
    public = key.public_key().export_key()
    #print(public)
    with open('key.pem','wb') as f:
        data = key.public_key().export_key()
        f.write(data)

    
        
    #print(pub)
    blockchain = Blockchain(key,key.public_key())

    certificates = ["Certificate 1: Issued to Alice", "Certificate 2: Issued to Bob", "Certificate 3: Issued to Charlie"]

    for cert in certificates:
        blockchain.add_certificate(cert)

    
   