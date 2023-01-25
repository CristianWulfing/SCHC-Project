#!/usr/bin/env python

from schc_handlers import SCHCNodeHandler
from schc_protocols import SCHCProtocol
from conn_layer import LoRaWANconn
from scapy.all import scapy
from scapy.layers.inet6 import IPv6, UDP, Raw
from datetime import datetime
import logging, time, serial

MTU = 32
handler = None
lora_conn = None

meter_conn           = None
meter_conn_port      = "/dev/ttyUSB0"
meter_conn_baud      = 9600
meter_conn_timeout   = 3

MODEM_SERIALPORT  = "/dev/ttyACM0"
MODEM_BAUDRATE    = 115200

LORA_DEVEUI = "70B3D57ED0055D4F"

downlink_queue = []

metrics_file = 'logs/' + datetime.now().strftime("%Y%m%d%H%M%S") + '_node_1_metrics.csv'

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG', datefmt='%d/%m/%y %H:%M:%S')

def SCHC_reading_callback(msg):

   logging.info(f"[SCHC] Reassembled: {msg.hex()}")
   pkt = scapy.layers.inet6.IPv6(msg)
   # pkt.show2()

   # Cleaning meter buffer
   while meter_conn.in_waiting > 0:
         meter_conn.readline()

   dlms_packet = bytes(pkt[UDP].payload)
   logging.info(f"[DLMS] Sending via Serial: {dlms_packet.hex()}")

   attempts_counter = 0

   ans = b''
   meter_conn.write(dlms_packet)
   time.sleep(0.2)

   while len(ans) == 0 and attempts_counter < 5:
      attempts_counter += 1
      logging.info(f"[DLMS] Reading Serial (attempt {attempts_counter} of 5)")
      while meter_conn.in_waiting > 0:
            ans += meter_conn.readline()

   logging.info(f"[DLMS] Receiving via Serial ({len(ans)}): {ans.hex()}")

   if len(ans) == 0:
      ans = b'\x00'

   downlink_queue.append({'ip_dest': pkt[IPv6].src, 'port_dest': pkt[UDP].sport, 'ip_src': pkt[IPv6].dst, 'port_src': pkt[UDP].dport, 'payload': ans})

def LoRa_on_message_callback(msg, port, snr, rssi):

   global handler
   msg_bytes = None

   if msg:
      msg_bytes = bytes(bytearray.fromhex(msg.decode()))
      logging.info(f"[LoRaWAN] Receiving on port {port}: {msg_bytes.hex()}")

   try:
      handler.handleMessage(msg_bytes, port, lora_conn, snr, rssi)

   except SystemExit as e:
      logging.info(f"[SCHC] SystemExit: {e}")

   except SystemError as e:
      logging.error(f"[SCHC] SystemError: {e}")

try:

   if meter_conn is None:
      meter_conn = serial.Serial(meter_conn_port, meter_conn_baud, timeout=meter_conn_timeout)
      meter_conn.reset_input_buffer()
      meter_conn.reset_output_buffer()

   if lora_conn is None:
      lora_conn = LoRaWANconn(MODEM_SERIALPORT, MODEM_BAUDRATE)

   if handler is None:
      handler = SCHCNodeHandler(SCHCProtocol.LoRaWAN, MTU, on_lora_message=LoRa_on_message_callback, on_receive_callback=SCHC_reading_callback, deveui=LORA_DEVEUI, metrics_file=metrics_file)

   while True:

      if len(downlink_queue) > 0:

         item = downlink_queue.pop(0)

         pkt = IPv6(src=item['ip_src'], dst=item['ip_dest']) / UDP(sport=item['port_src'], dport=item['port_dest']) / Raw(load=item['payload'])
         pkt.show2()
         package = bytes(pkt)
         handler.schedulePackage(package)
         reply = handler.sendPackage(lora_conn)

      else:

         handler.startLink(lora_conn)

except LoRaWANconn.TimeExpired:
   logging.error(f"[LoRaWAN] Erro no modem. Reiniciando")
except SystemExit as e:
   logging.info(f"[SCHC] SystemExit 1: {e}")
   handler = None
except SystemError as e:
   logging.error(f"[SCHC] SystemError: {e}")
   handler = None