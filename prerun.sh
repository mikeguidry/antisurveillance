iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP;ifconfig vmnet8 promisc
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP


