# XMPP bruteforce

The goal of this script is to bruteforce a password used to authenticate against SCRAM-SHA-1 mecanism in the context of an XMPP session over a .pcap capture.

## Theory : XMPP auth workflow to bruteforce

The workflow is the following :

1. The client normalizes the password with SASLPrep and picks a random string, called `clientNonce`.
The initialMessage is :
```
n,,"n=" .. username .. ",r=" .. clientNonce
```
This is base64-encoded by the client and sent to the server

2. The server responds with a base64-encoded challenge :
```
r=...,s=...,i=4096
```

- `r` is the `clientNonce` previsously received concatenated with `serverNonce`, a random string picked by the server
- `s` is the base-64 encoded salt
- `i` is the number of iterations

3. Client solves the challenge by making some calculations and sends a base64-encoded response :
```
c=...,r=...,p=...
```

- `c` is always `biws`
- `r` is exactly the same `serverNonce` as the one sent by the server in step 2
- `p` is the base64-encoded `clientProof`

The calculations are the following :

```
clientFinalMessageBare = "c=biws,r=" .. serverNonce

saltedPassword = PBKDF2-SHA-1(normalizedPassword, salt, i)
clientKey = HMAC-SHA-1(saltedPassword, "Client Key")
storedKey = SHA-1(clientKey)
authMessage = initialMessage .. "," .. serverFirstMessage .. "," .. clientFinalMessageBare
clientSignature = HMAC-SHA-1(storedKey, authMessage)
clientProof = clientKey XOR clientSignature

serverKey = HMAC-SHA-1(saltedPassword, "Server Key")
serverSignature = HMAC-SHA-1(serverKey, authMessage)

clientFinalMessage = clientFinalMessageBare .. ",p=" .. base64(clientProof)
```

4. If the challenge is considered solved by the server, it will send a `success` response containing a base64-encoded string :
```
v=...
```
The client has to make sure this `v` parameter matches the `serverSignature` described in the previous step.

### Test vector

1. Client has username `n`= user, password 'pencil', clientNonce `r`=fyko+d2lbbFgONRv9qkxdawL
   The initial message is : n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL

2. Server generates serverNonce 3rfcNHYJY1ZVvWVs7j and thus replies : r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
   The salt `s` is QSXCR+Q6sek8bf92 as b64, or 4125c247e43ab1e93c6dff76 as hex

3. The client must now solve the challenge
```
clientFinalMessageBare = c=biws,r= .. serverNonce
clientFinalMessageBare = c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j
```
```
saltedPassword = PBKDF2-SHA-1(normalizedPassword, salt, i)
saltedPassword = PBKDF2-SHA-1(SASLPrep("pencil"), 4125c24py7e43ab1e93c6dff76, 4096)
saltedPassword = 1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d
```
```
clientKey = HMAC-SHA-1(saltedPassword, "Client Key")
clientKey = HMAC-SHA-1(1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d, "Client Key")
clientkey = e234c47bf6c36696dd6d852b99aaa2ba26555728
```
```
storedKey = SHA-1(clientKey)
storedKey = SHA-1(e234c47bf6c36696dd6d852b99aaa2ba26555728)
storedKey = e9d94660c39d65c38fbad91c358f14da0eef2bd6
```
```
authMessage = initialMessage .. "," .. serverFirstMessage .. "," .. clientFinalMessageBare
authMessage = n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j
```

```
clientSignature = HMAC-SHA-1(storedKey, authMessage)
clientSignature = HMAC-SHA-1(e9d94660c39d65c38fbad91c358f14da0eef2bd6, n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j)
clientSignature = 5d7138c486b0bfabdf49e3e2da8bd6e5c79db613
```
```
clientProof = clientKey XOR clientSignature
clientProof = e234c47bf6c36696dd6d852b99aaa2ba26555728 XOR 5d7138c486b0bfabdf49e3e2da8bd6e5c79db613
clientProof = bf45fcbf7073d93d022466c94321745fe1c8e13b
```
```
serverKey = HMAC-SHA-1(saltedPassword, "Server Key")
serverKey = HMAC-SHA-1(1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d, "Server Key")
serverKey = 0fe09258b3ac852ba502cc62ba903eaacdbf7d31
```
```
serverSignature = HMAC-SHA-1(serverKey, authMessage)
serverSignature = HMAC-SHA-1(0fe09258b3ac852ba502cc62ba903eaacdbf7d31, n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j)
serverSignature = ae617da6a57c4bbb2e0286568dae1d251905b0a4
```
```
clientFinalMessage = clientFinalMessageBare .. ",p=" .. base64(clientProof)
clientFinalMessage = c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
```

## Usage

### Usage 1 : Simulate a SCRAM-SHA-1 XMPP auth

`simulate-auth` command.
Using the values of the test vector :

```
python3 xmpp_brute.py simulate-auth -s QSXCR+Q6sek8bf92 -l user -p pencil -clientNonce fyko+d2lbbFgONRv9qkxdawL -serverNonce 3rfcNHYJY1ZVvWVs7j -i 4096

Salted password : 1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d
Client key : e234c47bf6c36696dd6d852b99aaa2ba26555728
Stored key : e9d94660c39d65c38fbad91c358f14da0eef2bd6
Auth message : n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j
Client signature : 5d7138c486b0bfabdf49e3e2da8bd6e5c79db613
Client proof : bf45fcbf7073d93d022466c94321745fe1c8e13b
Server Key :0fe09258b3ac852ba502cc62ba903eaacdbf7d31
Server Signature : ae617da6a57c4bbb2e0286568dae1d251905b0a4
Client Final Message : c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
```

### Usage 2 : Bruteforce SCRAM-SHA-1 XMPP auth
`bruteforce` command.
This command will try to do a pure bruteforce of the password given the `p` param of the `clientFinalMessage` if you have it (you may have captured the traffic for example).
You can specify a starting pattern for the password with `-p` option if you're sure to know it, for instance :

```
python3 xmpp_brute.py bruteforce -s kM6lTjjnZW4F8WLboyagcA== -l thomas_user -p catlover -clientNonce fms4 -serverNonce Fe3A1scL7C0jtZsm+kcg96MWg769FuRu -i 4096 -response 785b3641e91df0947bc9b0ad6f786724c1847c88
Candidate password : catloverlgk
Found!
```

**WARNINGS** : 
- The `p` param of the `clientFinalMessage` MUST be hex-encoded
- The bruteforce is done over a predefined charset (variable `suffixes` in `run_cmd()` function). Feel free to change it for your needs.
- If you do not specify a `-p` (`--password`) option, the script will try to do a pure bruteforce without any prefix.