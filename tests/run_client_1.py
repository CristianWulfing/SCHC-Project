
import socket, logging

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG', datefmt='%d/%m/%y %H:%M:%S')

NODE_HOST       = "5454::e838:e51b:bc85:898c"
NODE_PORT       = 33334

dlmsDataList    = list()
auth            = "000100203fff00386036a1090607608574050801018a0207808b0760857405080201ac0a80083030303030303030be10040e01000000065f1f0400001e5dffff"
l3volt          = "000100203fff000dc001c100030100480700ff0200"
discon          = "000100203fff0009620380010003800100"

try:

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(300)
    s.connect((NODE_HOST, NODE_PORT))

    dlmsDataList.append(auth)

    while True:

        if len(dlmsDataList) > 0:
            payload = bytearray.fromhex(dlmsDataList.pop(0))
            s.send(payload)
            logging.info(f"[SOCKET] Sending to {NODE_HOST} on port {NODE_PORT}:\n    {payload.hex()}")

        try:
            data, addr = s.recvfrom(1024)
            if data:
                logging.info(f"[SOCKET] Receiving from {addr[0]} on port {addr[1]}:\n    {data.hex()}")

                if len(dlmsDataList) == 0:
                    if len(data) == 51 or len(data) == 17: # 51 = auth ok | 17 = reply ok
                        dlmsDataList.append(l3volt)
                    else:
                        dlmsDataList.append(auth)
        except socket.timeout:
            if len(dlmsDataList) == 0:
                dlmsDataList.append(l3volt)
finally:

    s.close()