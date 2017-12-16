iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP;ifconfig vmnet8 promisc

