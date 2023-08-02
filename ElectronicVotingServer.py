
import hashlib
import socket
import pickle



from Crypto.Cipher import AES
from Crypto.PublicKey import RSA




CANDIDATE_1="Democrat"

CANDIDATE_2="Republican"



def verify_zkp(vote,salt,x,y,u,v):
    u_check=hashlib.sha256(str(x*y).encode()).hexdigest()
    if u != u_check:
        return False
    v_check=hashlib.sha256(str(vote+salt+u).encode()).hexdigest()
    if v != v_check:
        return False
    return True


def main():

    IP=socket.gethostname()
    PORT=1234

    key = RSA.generate(AMOUNT_OF_BITS, None,VALUE_OF_e)

    privateK = int(str(key).replace("Private RSA key at ", ''), base=16)

    publicK = privateK * VALUE_OF_e

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((IP, PORT))

    server_socket.listen()

    (client, clientAddr) = server_socket.accept()

    print('Conncection from ' + str(clientAddr[0]) + ':' + str(clientAddr[1]))

    client.send(str(publicK).encode())

    publicK_ALICE = int(client.recv(5128).decode())

    secret = publicK_ALICE * privateK

    if len(str(secret)) > 16:
        newSecret = ''
        for x in str(secret):
            newSecret = newSecret + x
            if len(newSecret) == 16:
                break

    encrypted_votes=[]

    while True:
        data = client.recv(10000)
        if data.decode() == 'Vote':
            client.send('ok'.encode())
            data = pickle.loads(client.recv(10000))
            encrypted_votes.extend(data)



        elif data.decode() == 'Results':

            vote_tally = {CANDIDATE_1: 0, CANDIDATE_2: 0}
            for ciphertext, tag, nonce, encrypt_x, encrypt_x_tag, encrypt_y, encrypt_y_tag, u, v, encrypt_salt, encrypt_salt_tag in encrypted_votes:
                cipher = AES.new(newSecret.encode(), AES.MODE_EAX, nonce)
                vote = cipher.decrypt_and_verify(ciphertext, tag).decode()
                cipher = AES.new(newSecret.encode(), AES.MODE_EAX, nonce)
                x = int(cipher.decrypt_and_verify(encrypt_x, encrypt_x_tag).decode())
                cipher = AES.new(newSecret.encode(), AES.MODE_EAX, nonce)
                y = int(cipher.decrypt_and_verify(encrypt_y, encrypt_y_tag).decode())
                cipher = AES.new(newSecret.encode(), AES.MODE_EAX, nonce)
                salt = cipher.decrypt_and_verify(encrypt_salt, encrypt_salt_tag)
                if verify_zkp(vote, str(salt), x, y, u, v):
                    vote_tally[vote] += 1

            msg = "Vote tally: "
            for cand in vote_tally.keys():
                msg += "{}: {} votes.".format(cand, vote_tally[cand])


            client.send(msg.encode())
        elif data.decode()=='exit':
            break


if __name__=="__main__":
    main()