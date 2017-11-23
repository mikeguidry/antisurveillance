# anti surveillance python example/testing
# itll be easy enough for a child to use.

import antisurveillance
from pprint import pprint
from time import sleep

# iterates all attack structures X times, or 0 forever.. but ensure you have other ways to kill it.. just allowing it
def perform(a,b):
	count = 0
	while (count < b or b == 0):
		if ((count % 10) == 0):
			print("AS_perform() - Count is %d") % count
		a.attackperform()
		count = count + 1
		if (b == 0):
			sleep(0.05)

#build an HTTP session and add it as an attack.. itll get enabled immediately
def build_http(a):
	server_body = open("server_body", 'rU').read()
	client_body = open("client_body", 'rU').read()
	src_ip = "10.0.0.1"
	dst_ip = "10.0.0.2"
	src_port = 31337
	dst_port = 80
	ret = a.buildhttp(src_ip, src_port, dst_ip, dst_port, client_body, server_body)

	print("new attack ID %d") % ret

#build an http session portion by portion..
#you can use ths to build any type of protocol.. by crafting the packet from each side
def other_build_http(a):
	server_body = open("server_body", 'rU').read()
	client_body = open("client_body", 'rU').read()
	src_ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	dst_ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7335"
	src_port = 31338
	dst_port = 80
	client_ttl = 64
	server_ttl = 53
	client_window = 1500 - ((20 * 2) + 12)
	server_window = client_window

	#create new instructions
	a.instructionscreate(client_ip=src_ip, client_port=src_port, destination_ip=dst_ip, destination_port=dst_port, client_ttl=client_ttl, server_ttl=server_ttl, client_window_size=client_window, server_window_size=server_window)

	#lets open the connection (perform 3 way handshake packets)
	a.instructionstcpopen()

	#now we want to send a request fromm the client to the server (HTTP GET)
	a.instructionstcpsend(from_client=1, data=client_body)

	#now the server needs to respond
	a.instructionstcpsend(from_client=0, data=server_body)

	#now the connection gets closed from the client side (noo more requests)
	a.instructionstcpclose(from_client=1)

	#now build the attack structure around those instructions we just designed
	#skip adjustments is for replaying attacks not wanting to generate new IPs
	ret = a.instructionsbuildattack(count=999, interval=1, skip_adjustments=0)

	print("new attack ID %d") % ret


#main function that gets called from anti
#it should perform the duties.. and it could loop to continue executing
def init():
	# this should be removed and done completely in C.. i need to see how the object is allocated and hook it or somethiing..
	# would rather work on other stuff first ***
	a = antisurveillance.manager()
	a.setctx(ctx)

	#pprint(a)

	#you could load a previously dumped pcap.. so it would expand, and replay those sessions -- and dump the updated pcap at the end
	#loop a few times and see how much the sessions/packets grow
	#a.pcapload(filename="py_output.pcap")
	#a.pcapload(filename="tcp6.pcap")

	#turn networking off so that we will dump all packets, and they wont get wrote to the live internet
	a.networkoff()

	#build an HTTP session
	build_http(a)

	#build http session using the raw way (meant for other protocols as well)
	#this can work for POP/SMTP/etc
	other_build_http(a)

	#iterate 30 times AS_perform() (pushes packets to outgoing queue, etc)
	#You can loop this and it would go on forever...right now the app can be used perfectly.
	perform(a,100)

	# how many packets did that generate?
	print("network queue count: %d") % a.networkcount()

	#pcap saving to open it in wireshark
	a.pcapsave("py_output.pcap")


	#could turn network dumping on...
	#a.networkon()

	#and loop for awhile...?
	#just be sure the counts are high enoough for each attack structure...
	#perform(a,99999) or (a,0) forever...

	# i was calling disable() because it was running the C code right after.. it ignores it now if it returns 1 here
	#a.disable()

	return 1
	

# this is the function that gets called every iteration if running from the C side.. (Scripting_Perform())
#this is irrelevant if your returning 1, or not doing anything in C that loops...
def script_perform():
	return 0
