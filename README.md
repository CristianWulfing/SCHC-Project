# SCHC-Project

SCHC communication protocol Python implemention based on the work of [PySCHC](https://github.com/niclabs/PySCHC), according to [RFC8724](https://datatracker.ietf.org/doc/html/rfc8724) and [RFC9011](https://datatracker.ietf.org/doc/html/rfc9011). This work consider the whole SCHC protocol (compression and fragmentation) applied to a real enviroment. It runs the communication between IPv6/UDP applications and a Smart Meter connected to a Raspberry Pi 3 over LoRaWAN. A second Node is used in order to evaluate the network accuracy.

This project was financed in part by the Coordenação de Aperfeiçoamento de Pessoal de Nível Superior – Brasil (CAPES) – Finance Code 001 and the companies Mux Energia and Fox IoT, by the R&D project ANEEL PD-00401-0005/2020.

Furthermore, the project was used in my undergraduate thesis in order to complete the Computer Engineer degree at Federal University of Santa Maria (UFSM) - Brazil.

---

## First Steps

### Dependencies setup

    $ pip install -r requirements.txt

### PySCHC library setup

    $ python src/setup.py develop 

### Linux tun setup

    $ sudo ip tuntap add mode tun name tun0
    $ sudo ip link set tun0 up
    $ sudo ip -6 addr add abcd::10 dev tun0
    $ sudo ip -6 route add 5454::/64 dev tun0

### Gateway

    $ sudo python run/run_gateway.py

### Application 1

    $ sudo python run/run_client_1.py

### Application 2

    $ sudo python run/run_client_2.py

### Node 1

    $ sudo python run/run_node_1.py

### Node 2

    $ sudo python run/run_node_2.py

---

## Copyright

&copy; 2021 NIC Chile Research Labs

&copy; 2023 Fox IoT

&copy; 2023 Cristian Augusto Wülfing