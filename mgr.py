import antisurveillance
from pprint import pprint

def init():
	# this should be removed and done completely in C.. i need to see how the object is allocated and hook it or somethiing..
	# would rather work on other stuff first ***
	a = antisurveillance.Config()
	a.setctx(ctx)

	# rest of code here...
	pprint(antisurveillance.Config)
	print("hi\n")
	l = [a]
	a.first = "first name"
	a.last = "last name"
	print("hi2222\n")
	#print(a.networkoff())
        print(a.networkoff())	
	a.pcapload("several.pcap")
	count = 0
	while (count < 30):
		print(" Count is %d") % count
		a.attackperform()
		count = count + 1
	print("network queue")
	print(a.networkcount())
	print("Done\n")

