# anti surveillance python example/testing
# itll be easy enough for a child to use.

import antisurveillance
from pprint import pprint

# iterates all attack structures X times
def perform(a,b):
	count = 0
	while (count < b):
		print("AS_perform() - Count is %d") % count
		a.attackperform()
		count = count + 1

#build an HTTP session and add it as an attack.. itll get enabled immediately
def build_http4(a):
	server_body = open("server_body", 'rU').read()
	client_body = open("client_body", 'rU').read()
	src_ip = "10.0.0.1"
	dst_ip = "10.0.0.2"
	src_port = 31337
	dst_port = 80
	a.buildhttp4(src_ip, src_port, dst_ip, dst_port, client_body, server_body)

def init():
	# this should be removed and done completely in C.. i need to see how the object is allocated and hook it or somethiing..
	# would rather work on other stuff first ***
	a = antisurveillance.manager()
	a.setctx(ctx)

	pprint(a)

	#turn networking off so that we will dump all packets, and they wont get wrote to the live internet
	a.networkoff()

	#build an HTTP session
	build_http4(a)

	#iterate 30 times AS_perform() (pushes packets to outgoing queue, etc)
	#You can loop this and it would go on forever...right now the app can be used perfectly.
	perform(a,30)

	print("network queue count: %d") % a.networkcount()
	#pcap saving
	a.pcapsave("py_output.pcap")


	# i was calling disable() because it was running the C code right after.. it ignores it now if it returns 1 here
	a.disable()

	#returning 1 will stop the C portion of the code...
	#so itll only work with python
	return 1
	
