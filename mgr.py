import antisurveillance
from pprint import pprint

# iterates all attack structures X times
def perform(a,b):
	count = 0
	while (count < b):
		print("AS_perform() - Count is %d") % count
		a.attackperform()
		count = count + 1

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
	a = antisurveillance.Config()
	a.setctx(ctx)

	pprint(a)

	build_http4(a)

	perform(a,30)

