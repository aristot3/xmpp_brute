# coding=utf-8

import argparse
import binascii
import hashlib
import hmac
import base64
from itertools import chain, product
from argparse import RawDescriptionHelpFormatter

def get_args_parser():

    parser = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(help="Available commands", dest="command")
    simulate_auth_parser = subparsers.add_parser(
        "simulate-auth", help="Simulate a SCRAM-SHA-1 XMPP authentication and outputs the results"
    )
    simulate_auth_parser.add_argument(
        "-l", "--login", help="Login", required=True
    )
    simulate_auth_parser.add_argument(
        "-p", "--password", help="Password", required=True
    )
    simulate_auth_parser.add_argument(
        "-s", "--salt", help="Salt sent by the server (base64)", required=True
    )
    simulate_auth_parser.add_argument(
        "-i", "--iterations", help="Number of iterations", required=True
    )
    simulate_auth_parser.add_argument(
        "-clientNonce", "--clientNonce", help="clientNonce", required=True
    )
    simulate_auth_parser.add_argument(
        "-serverNonce", "--serverNonce", help="serverNonce", required=True
    )

    bruteforce_parser = subparsers.add_parser(
        "bruteforce", help="Bruteforces the password. The login must be contained in the password"
    )
    bruteforce_parser.add_argument(
        "-l", "--login", help="Login", required=True
    )
    bruteforce_parser.add_argument(
        "-s", "--salt", help="Salt sent by the server (base64)", required=True
    )
    bruteforce_parser.add_argument(
        "-i", "--iterations", help="Number of iterations", required=True
    )
    bruteforce_parser.add_argument(
        "-clientNonce", "--clientNonce", help="clientNonce", required=True
    )
    bruteforce_parser.add_argument(
        "-serverNonce", "--serverNonce", help="serverNonce", required=True
    )
    bruteforce_parser.add_argument(
        "-response", "--finalresponse", help="p parameter of the client final response, for instance : 'v0X8v3Bz2T0CJGbJQyF0X+HI4Ts='", required=True
    )
    bruteforce_parser.add_argument(
        "-p", "--passwordfragment", help="First known chars of the password", required=False
    )

    return parser

def to_hex(s):
    return int(s, base=16)

def simulate_auth(args_parsed):
    salt = binascii.unhexlify(base64.b64decode(args_parsed.salt).hex()) 
    unsalted_pwd = (args_parsed.password).encode("utf8")
    salted_pwd = hashlib.pbkdf2_hmac('sha1', unsalted_pwd, salt, 4096) 

    client_key = hmac.new(salted_pwd, b'Client Key', hashlib.sha1) 
    stored_key = hashlib.sha1(client_key.digest()) 

    auth_message = "n=" + args_parsed.login + ",r=" + args_parsed.clientNonce +\
    ",r=" + args_parsed.clientNonce + args_parsed.serverNonce + ",s=" +\
    args_parsed.salt + ",i=" + args_parsed.iterations + ",c=biws,r=" +\
    args_parsed.clientNonce + args_parsed.serverNonce 

    client_signature = hmac.new(stored_key.digest(),\
                                bytes(auth_message, "utf8"),\
                                hashlib.sha1) 

    client_proof = str(
                        hex(
                            to_hex(
                                client_key.hexdigest()) ^\
                                to_hex(client_signature.hexdigest()
                                )
                            )
                        )[2:] 
    
    server_key = hmac.new(salted_pwd, b'Server Key', hashlib.sha1)
    server_signature = hmac.new(server_key.digest(),\
                                bytes(auth_message, "utf8"),\
                                hashlib.sha1) 

    if args_parsed.command == "simulate-auth":
        print("Username : " + args_parsed.login)
        print("Password : " + args_parsed.password)
        print("Salted password : " + salted_pwd.hex())
        print("Client key : " + client_key.hexdigest())
        print("Stored key : " + stored_key.hexdigest())
        print("Auth message : " + auth_message)
        print("Client signature : " + client_signature.hexdigest())
        print("Client proof : " + client_proof)
        print("Server Key :" + server_key.hexdigest())
        print("Server Signature : " + server_signature.hexdigest())

    return client_proof

def bruteforce(charset, maxlength):
    return (''.join(candidate)
        for candidate in chain.from_iterable(product(charset, repeat=i)
        for i in range(1, maxlength + 1)))

def run_cmd(args_parsed):
    if args_parsed.command == "bruteforce":
        if args_parsed.passwordfragment :
            temp_password = args_parsed.passwordfragment
        else:
            temp_password = ""
        args_parsed.password = temp_password

        suffixes = list(bruteforce('_abcdefghijklmnopqrstuvwxyz', 3))
        i = 0

        while i != len(suffixes) :
            args_parsed.password= temp_password + suffixes[i]
            print("Candidate password : " + args_parsed.password)
            i += 1
            result = simulate_auth(args_parsed)
            print("Resultat : " + result)
            print("Client Final Response to meet : " +\
                   args_parsed.finalresponse + "\n")

            if result == args_parsed.finalresponse :
                print("Found !\nPassword is : " + args_parsed.password)
                i = len(suffixes)
    else:
        simulate_auth(args_parsed)


def main():
    args_parser = get_args_parser()
    args_parsed = args_parser.parse_args()

    run_cmd(args_parsed)

if __name__ == "__main__":
    main()

