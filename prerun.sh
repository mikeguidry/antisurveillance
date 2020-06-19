iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP;ifconfig ens33 promisc
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP


