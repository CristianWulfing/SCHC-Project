
# tun setup
sudo ip tuntap add mode tun name tun0
sudo ip link set tun0 up
sudo ip -6 addr add abcd::10 dev tun0
sudo ip -6 route add 5454::/64 dev tun0

# gateway
clear && sudo python -u run_gateway.py 2>&1 | tee -a logs/$(date -d "today" +"%Y%m%d%H%M%S")_gateway.log

# client 1
clear && sudo python -u run_client_1.py 2>&1 | tee -a logs/$(date -d "today" +"%Y%m%d%H%M%S")_client_1.log

# client 2
clear && sudo python -u run_client_2.py 2>&1 | tee -a logs/$(date -d "today" +"%Y%m%d%H%M%S")_client_2.log

# node 1
clear && sudo python -u run_node_1.py 2>&1 | tee -a logs/$(date -d "today" +"%Y%m%d%H%M%S")_node_1.log

# node 2
clear && sudo python -u run_node_2.py 2>&1 | tee -a logs/$(date -d "today" +"%Y%m%d%H%M%S")_node_2.log