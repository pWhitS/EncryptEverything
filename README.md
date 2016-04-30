# EncryptEverything

## What is it?
This is a Chrome extenxion implementing PGP style encryption capabilities. It can be used to encrypt text in any web-based medium and decrypt the result.

## Who made it?
This project was a collaboration by **Patrick Whitsell** (pdw236@nyu.edu), **Casey McGinley** (cmm771@nyu.edu), and **Fernando Maymi** (fernando.maymi@nyu.edu). The extension was made as part of their **Applied Cryptography (CS-GY 6903)** class taught by **Prof. Giovanni Di Crescenzo**

## What external libraries/sources does it use?
- **Stanford Javascript Crypto Library (sjcl)**
  - used for symmetric encryption of payloads (AES-256 CCM), hashing (SHA256), encoding (hex, base64, etc.) and a few other things
  - https://github.com/bitwiseshiftleft/sjcl
  - Configured with:
```
./configure --without-all --with-aes --with-ctr --with-sha256 --with-random --with-hmac --with-codecBase64 --with-codecHex --with-bitArray --with-convenience
```
- **JSEncrypt**
  - used for asymmetric encryption for the purposes of key exchange and digital signatures (RSA 2048-bit keys)
  - we modified this slightly to allow us to encrypt with a private key
  - https://github.com/travist/jsencrypt
- **SweetAlert**
  - used for aesthetics
  - https://t4t5.github.io/sweetalert/

## How do I load it into Chrome?
- Clone this repo
- Open Chrome
- Go to: Settings --> Extensions
- Make sure the "Developer Mode" box is checked
- Click "Load unpacked extension..."
- Select your local copy of the EncryptEverything repo

## But how do I use it?
- First, you'll need a pair of public and private RSA keys, 2048-bit in standard RSA PEM format
  - The best way to do this is with ssh-keygen, standard in most bash environments and availble in Git Bash on Windows
  - First, generate your key pair (see first code block below)
  - When complete, you will get two files, id_rsa and id_rsa.pub
  - id_rsa is your private key and it is already in the correct format
  - id_rsa.pub needs to be converted to PEM format (see 2nd code block below)
  - Alternatively, if you are just looking to test this out and don't care where the keys come from, you can use this online RSA key generator from JSEncrypt
  - http://travistidwell.com/jsencrypt/demo/index.html

Generate keys:
```
ssh-keygen -t rsa -b 2048
```
Convert .pub to .pem:
```
ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem
```
- Now that you have your keys, click the extenstion and hit "Manage"
- Here, you can copy and paste your private key, as well as some identifier for yourself (email works well)
- You will also provide a password when entering your private key, **don't forget it**
- Now you must enter the public keys
  - If you just wish to test this out on your own keyset, then just add your public key here with the same identifier you used for your private key
  - Otherwise, you must find some friends and get their public keys :)
- Once all the keys are imported, hit "Close"
- You are ready to encrypt!
  - Highlight the text you want to encrypt
  - Open the extension and hit "Encrypt"
  - Select the person you are sending this message to
  - Press "Select"
  - Enter your password to decrypt the private key from storage
  - If successful, the encrypted text is copied to your clipboard and you can paste it where you will
- You can also decrypt if you have some encrypted payload
  - Highlight the encrypted text
  - Press "Decrypt"
  - Provide your password to decrypt your private key
  - If successful, your plaintext message is revealed; pressing "Copy" will add it to your clipboard
- Some final thoughts
  - You will not be able to decrypt the same encrypted payload twice due to our attempts to thwart replay attacks
  - Don't forget your password for your private key; if you do you'll need to enter the private key again
  - If you want to send messages to others you will need to exchange public keys first (we don't provide an infrastructure to do this for you)

## What cryptographic primitives/methods does it make use of?
- Asymmetric encryption
  - RSA-2048
  - Confidentiality, key exchange
- Symmetric encryption
  - AES-256 CCM mode (CTR + CBC-MAC)
  - Confidentiality
- Hash
  - SHA256
  - Integrity
- Digital signature
  - SHA256 hash encrypted by 2048-bit RSA private key
  - Integrity, authenticity
- Nonce
  - Timestamp (in milliseconds)
  - Replay detection

## What security concerns does it satisfy?
- Confidentiality
- Integrity
- Authenticty
- Replay detection
