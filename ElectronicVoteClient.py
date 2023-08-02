

import hashlib
import os
import random
import socket
import pickle


import pandas as pd

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

def generate_salt():
    salt=os.urandom(16)
    return salt

def generate_password_hash(salt,password):
    password_hash=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,100000)
    return password_hash


def auth_voter(salt,password_hash,password_attempt):
    password_attempt_hash=hashlib.pbkdf2_hmac('sha256',password_attempt.encode(),salt,100000)
    if password_attempt_hash==password_hash:
        return True
    else:
        return False



def gen_zkp(vote,salt):

    #random values for proof
    x=random.randint(0,100)
    y=random.randint(0,100)

    #value calculation for proof
    u=hashlib.sha256(str(x*y).encode()).hexdigest()
    v=hashlib.sha256(str(vote+salt+u).encode()).hexdigest()

    return (x,y,u,v)





def main():

    IP="SERVER_IP"
    PORT=SERVER_PORT

    key=RSA.generate(AMOUNT_OF_BITS,None,VALUE_OF_e)

    privKey=int(str(key).replace("Private RSA key at ",''),base=16)
    pubKey=privKey*VALUE_OF_e

    clientSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    clientSock.connect((IP,PORT))

    pubKeyBob=int(clientSock.recv(5128).decode())

    clientSock.send(str(pubKey).encode())

    secret=pubKeyBob*privKey

    if len(str(secret))>16:
        newSecret=''
        for x in str(secret):
            newSecret=newSecret+x
            if len(newSecret)==16:
                break

    voters=pd.read_csv('voters.csv')
    voter_info=[]
    for index,row in voters.iterrows():
        salt = generate_salt()
        hash=generate_password_hash(salt,row['password'])
        voter_info.append((salt,hash))







    while True:
            encrypted_votes = []
            center = int(input("Choose center (1-10): "))
            id = int(input("Welcome to voting center {} , please enter your ID: ".format(center)))
            if id not in voters['id'].values:
                print("ID doesn't exist")
                continue
            password_attempt = input("Enter password: ")
            index=voters[voters['id']==id].index[0]
            salt,password_hash=voter_info[index]
            auth = auth_voter(salt, password_hash, password_attempt)
            if not auth:
                print("Incorrect password, please try again.")
                continue
            elif center not in voters[voters['id'] == id]['center'].values:
                print("Wrong center")
                continue

            choice=input("Voter is authenticated. Choose your action (Vote-1,See Results-2,Exit-3) :")
            if choice=='1':
                if 0 not in voters[voters['id'] == id]['ifVoted'].values:
                    print("You already voted")
                    continue
                vote = input("Enter vote (Democrat or Republican):")
                cipher=AES.new(newSecret.encode(),AES.MODE_EAX)
                nonce=cipher.nonce
                ciphertext,tag=cipher.encrypt_and_digest(vote.encode())
                zkp = gen_zkp(vote, str(salt))
                cipher = AES.new(newSecret.encode(), AES.MODE_EAX,nonce)
                encrypt_x=cipher.encrypt_and_digest(str(zkp[0]).encode())
                cipher = AES.new(newSecret.encode(), AES.MODE_EAX,nonce)
                encrypt_y=cipher.encrypt_and_digest(str(zkp[1]).encode())
                cipher = AES.new(newSecret.encode(), AES.MODE_EAX,nonce)
                encrypt_salt=cipher.encrypt_and_digest(salt)
                encrypted_votes.append((ciphertext, tag,nonce, encrypt_x[0],encrypt_x[1],encrypt_y[0],encrypt_y[1],zkp[2],zkp[3],encrypt_salt[0],encrypt_salt[1]))
                voters.loc[index,'ifVoted']=1
                clientSock.send('Vote'.encode())
                clientSock.recv(10000)
                data=pickle.dumps(encrypted_votes)
                clientSock.send(data)

            elif choice=='2' :
                clientSock.send('Results'.encode())
                msg=clientSock.recv(10000)
                print(msg.decode())

            elif choice=='3':
                clientSock.send('exit'.encode())
                break


if __name__=="__main__":
    main()