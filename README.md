# Encrypted Electronic Voting System with ZKP
 A client-server electronic voting system utilizing AES and RSA encryption and Diffie-Hellman key exchange and ZKP (Zero Knowledge Proof) method to transfer voter's login credentials and votes securely.


## Prerequisites:

Install Python 3.9

Install from [here](https://www.python.org/downloads/) for Windows

Or use the following command:

```bash

sudo apt-get install python==3.9

```

Than install additional libraries using pip install:

```bash

python3 -m pip install hashlib os random socket pickle pandas

```

## Run

Run the server:

```bash

python3 -m ElectronicVotingServer.py 

```

Than the client:

```bash

python3 -m ElectronicVotingClient.py 

```