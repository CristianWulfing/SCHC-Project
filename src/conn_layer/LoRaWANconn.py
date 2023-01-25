
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

import serial, time, re, logging

class LoRaWANconn:

   ser = None
   port = None

   def __init__(self, serialPort, baudRate):

      try:
         self.ser = serial.Serial(serialPort, baudRate, timeout=3)
         self.ser.reset_input_buffer()
         self.ser.reset_output_buffer()

         self.joinTime()
      except:
         self.ser.close()

   class TimeExpired(Exception):
      pass

   def joinTime(self):

      ans = b""
      t = time.time()
      self.ser.write(("AT+JOIN\r\n").encode("utf-8"))
      time.sleep(0.2)
      while ans.count(b"Done") == 0 and ans.count(b"already") == 0:

         read = self.ser.readline()
         print(read)
         ans += read 

         if time.time() - t > 25:
               raise self.TimeExpired("More than 25 secs without answer")

   def sendTime(self, payload, port):

      if(port != self.port):

         logging.info(f"[LoRaWAN] Setting up LoRaWAN on port {port}")
         self.ser.write(("AT+PORT=" + str(port) + "\r\n").encode("utf-8"))
         time.sleep(0.2)
         while self.ser.in_waiting > 0:
               ans = self.ser.readline()
               if ans != b"\r\n":
                  print(ans)
         self.port = port

      logging.info(f"[LoRaWAN] Sending on port {self.port}: {payload.hex()}")

      self.ser.reset_input_buffer()
      self.ser.reset_output_buffer()

      ans = b""
      while ans.count(b"Done") == 0:

         if ans.count(b"No free channel") > 0:
            time.sleep(0.5)

         self.ser.write(('AT+MSGHEX=\"' + str(payload.hex()) + ('"\r\n')).encode('UTF-8'))
         time.sleep(0.2)
         ans=self.waitForDone()

      return self.parse_ans(ans)

   def waitForDone(self):
      ans = b""
      t = time.time()
      
      while ans.count(b"Done") == 0 and ans.count(b"No free channel") == 0:
         if self.ser.in_waiting > 0:
               read = self.ser.readline()
               print(read)
               ans += read 
         if time.time() - t > 25:
               raise self.TimeExpired("More than 25 secs without answer")

      return ans

   def parse_ans(self, l):
      idx=l.find(b"RSSI")
      if (idx != -1):

         parser = re.findall(r"[-+]?(?:\d*\.*\d+)", str(l[idx:]))
         rssi = float(parser[0])
         snr = float(parser[1])

         start_port = b"PORT: "
         iport = l.find(start_port)
         if (iport != -1):
            start_rx = b"RX: "
            end_rx = b" \r\n"
            irx = l.find(start_rx)

            port = int((re.findall(r'\d+', str(l[iport+len(start_port):irx])))[0])
            rx = (l[irx+len(start_rx)+1:l.rfind(end_rx)-2])
            
            return(1,snr,rssi,rx,port)
            
      return(0,0,0,"", None)