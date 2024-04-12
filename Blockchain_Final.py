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

    def compute_hash(self, block):
        block_content = block.copy()
        block_content = {key: block_content[key] for key in block_content if key != 'signature'}
        encode = json.dumps(block_content, sort_keys=True).encode()
        return hashlib.sha512(encode).hexdigest()

    def proof_of_work(self, index, previous_hash, transactions):
        nonce = 0
        while True:
            if self.validate(index, previous_hash, transactions, nonce):
                return nonce
            nonce += 1

    def validate(self, index, previous_hash, transactions, nonce):
        data = f"{index}{previous_hash}{transactions}{nonce}".encode()
        hashed = hashlib.sha512(data).hexdigest()
        return hashed.startswith(self.difficulty)

    def add_certificate(self, certificate_hash):
        last_block = self.chain[-1]
        index = last_block['index'] + 1
        previous_hash = self.compute_hash(last_block)
        nonce = self.proof_of_work(index, previous_hash, [certificate_hash])
        
        block = {
            'index': index,
            'timestamp': time.time(),
            'transactions': [certificate_hash],
            'nonce': nonce,
            'previous_hash': previous_hash,
        }
        block['signature'] = self.sign_block(block).hex()
        self.chain.append(block)

    def verify_certificate(self, certificate_hash):
        for block in self.chain:
            if certificate_hash in block['transactions']:
                return True
        return False

    def verify_signature(self,block,public_key):
        signature = block['signature']
        byteform = bytes.fromhex(signature)
        content = block.copy()
        content = {key: content[key] for key in content if key != 'signature'}

        try:
            hash_block = SHA512.new(json.dumps(content).encode())
            pkcs1_15.new(public_key).verify(hash_block,byteform)
            return True
        except (ValueError,TypeError):
            return False

   

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

    
 
    while True:
        print(" ########################################################\n",
            "############ Block Chain Final Assignment ##############\n",
            "############ Acedamic Document File System #############\n",
            "########################################################\n")
        print("Welcome to the Academic Document File System\n\n What would you like to do?\n\n 1. Access Documents\n\n 2. Store new document\n\n")
        action = input("Enter your choice: ")

        if action == "1":
            
            block_id = int(input("Please enter the ID of the document you'd like to access: "))
            check_action = input("Would you like to\n1. Display certificate\n2. Verify Certificate\n3. Verify Digital Signature\n")
            if check_action == '1':
                print(blockchain.chain[int(block_id)])
            elif check_action == '2':
                cert_to_verify = certificates[block_id]
                cert_validity = blockchain.verify_certificate(cert_to_verify)
                print(f"\nCertificate '{cert_to_verify}' valid: {cert_validity}")
            elif check_action == '3':
                key_file = input("Please type the name of key file. (format: key.pem)\n")
                with open('key.pem','rb') as f:
                    data = f.read()
                    public = RSA.import_key(data)
                    if blockchain.verify_signature(blockchain.chain[block_id],public):
                        print('Digital Signature is valid')
                    else:
                        print('file may be tampered with')


        elif action == "2":
            name = input("Please enter your name: ")
            certificates.append("Certificate " + str(len(certificates)) + ": Issued to " + name)
            print(certificates[-1], 'has been successfully added\n')
            blockchain.add_certificate(certificates[-1])  