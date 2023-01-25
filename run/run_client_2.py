#!/usr/bin/env python

# **************************************************************************
#   SCHC PROJECT
# **************************************************************************
#   AUTHOR: CRISTIAN AUGUSTO WüLFING
#   EMAIL: cris_wulfing@hotmail.com
#   CITY: Santa Maria - Rio Grande do Sul - Brasil
#   FOUNDATION: Fox IoT
# **************************************************************************
#   Copyright(c) 2023 Fox IoT.
# **************************************************************************

import socket, logging, random, string

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG', datefmt='%d/%m/%y %H:%M:%S')

NODE_HOST       = "5454::925a:bf5d:c5ce:2f9"
NODE_PORT       = 33334

def generate_random_payload(length : int):

   characters = string.ascii_letters + string.digits
   return (''.join(random.choice(characters) for i in range(length))).encode('utf-8')

try:

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(600)
    s.connect((NODE_HOST, NODE_PORT))

    while True:

        ran = random.randint(1,512)
        payload = bytearray.fromhex(generate_random_payload(ran).hex())

        try:
            s.send(payload)
            logging.info(f"[SOCKET] Sending to {NODE_HOST} on port {NODE_PORT}:\n    {payload.hex()}")

            data, addr = s.recvfrom(1024)
            if data:
                logging.info(f"[SOCKET] Receiving from {addr[0]} on port {addr[1]}:\n    {data.hex()}")
        except socket.timeout:
            logging.info(f"[SOCKET] Timeout")

finally:

    s.close()