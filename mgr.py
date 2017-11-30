# anti surveillance python example/testing
# itll be easy enough for a child to use.

import antisurveillance

from pprint import pprint
from time import sleep, time
import signal
import sys
import socket
import random
import struct
import os.path
import readline
import code
import encodings
import gc

perform_counter = 0

#temporary fix for crash.. have to ensure all of my code is using correct references (inc/decrease)
# i needed to disable so interactive console works :)
gc.disable()


#support ctrl-c to stop infinite loop in perform()
def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    mgr = antisurveillance.manager()
    mgr.exit()
    sys.exit(0)
        
#install signal handler for SIGINT (ctrl-c)        
signal.signal(signal.SIGINT, signal_handler)

#traceroute a randop IP whenever the queue is completed.. this will help us have more data
#for IP generation strategies to ensure we affect the most surveillance platforms
def traceroute_random_ip(a,b):
    cnt = a.traceroutecount()
    while (cnt < b):
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        a.traceroutequeue(target=ip)
        cnt = cnt + 1

#add DNS results from top sites into traceroute queue
#the purpose is so we can automatically target mass surveillance platforms worldwide
# in all countries without requiring any data ahead of time except some IPs
# to start to help us get routes, and then we will add random IPs afterwards
def top_sites_research(a):
    lines = open("top1m_resolved.txt").readlines()
    random.shuffle(lines)
    for ip in lines:
        a.traceroutequeue(target=ip)


# iterates all attack structures X times, or 0 forever.. but ensure you have other ways to kill it.. just allowing it
def perform(a,b):
    count = 0
    while (count < b or b == 0):
        if (count and (count % 50000) == 0):
            print("AS_perform() - Count is %d") % count
            d = a.networkcount()
            e = a.attackcount()
            print("Network Queue Count {} Attack Count {}").format(d,e)
        a.attackperform()
        count = count + 1

    # if looping infinite.. then we must control the timing so it doesnt use up the entire CPU
    if (b == 0):
        sleep(0.5)

#build an HTTP session and add it as an attack.. itll get enabled immediately
def build_http(a): 
    server_body = open("server_body", 'rU').read()
    client_body = open("client_body", 'rU').read()
    src_ip = "10.0.0.1"
    dst_ip = "10.0.0.2"
    src_port = 31337
    dst_port = 80
    ret = a.buildhttp(src_ip, src_port, dst_ip, dst_port, client_body, server_body, count=99999)

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
    ret = a.instructionsbuildattack(count=999999999, interval=1, skip_adjustments=0)

    print("new attack ID %d") % ret


# if this were to be a script which would get called periodically after init() is completed...
# then use script_enable().. and script_perform() would get called every iteration
# and the program would not exit...
def script_enable(a):
    a.scriptenable()


# i wanted to way to enable/disable the debug console mid execution..
def debug_console(a):
    fname = "debug_console"
    e = os.path.exists(fname)
    if e is True:
        variables = globals().copy()
        variables.update(locals())
        shell = code.InteractiveConsole(variables)
        shell.interact()
        os.remove(fname)


def script_reload():
    import mgr
    reload(mgr)

# this is the function that gets called every iteration if running from the C side.. (Scripting_Perform())
# the software will call AS_perform() itself out of the this scope.. so no need to call the one above in python
# otherwise the script has full control.. including the timing.. so use some or it might eat all CPU
def script_perform():
    #sleep(0.1)
    a = antisurveillance.manager()
    a.setctx(ctx)

    debug_console(a)

    
    # how many packets did that generate?
    print("network %05d attack %05d traceroute queue %05d\n") % (a.networkcount(), a.attackcount(), a.traceroutecount())
    

    #traceroute_random_ip(a)
    cnt = a.traceroutecount()
    if (cnt == 0):
        #traceroute_random_ip(a,1000)
        a.tracerouteretry()
        #print("traceroute count 0 .. adding");
        #a.traceroutequeue(target="8.8.8.8")
        #a.traceroutequeue(target="9.9.9.9")
        #a.traceroutequeue(target="4.2.2.1")
        #a.traceroutequeue(target="1.2.3.4")
        #a.traceroutequeue(target="172.217.9.14")
        #traceroute_random_ip(a)

    #cnt = a.traceroutecount()
    #print("Traceroute queue count is %d") % cnt
    sleep(1)

    

    return 0



#main function that gets called from anti
#it should perform the duties.. and it could loop to continue executing
def init():
    # get a pointer? inn python?  to the manager so we can interface w it
    a = antisurveillance.manager()

    # this should be removed and done completely in C.. i need to see how the object is allocated and hook it or somethiing..
    # would rather work on other stuff first ***
    a.setctx(ctx)

    #pprint(a)

    #you could load a previously dumped pcap.. so it would expand, and replay those sessions -- and dump the updated pcap at the end
    #loop a few times and see how much the sessions/packets grow
    #a.pcapload(filename="py_output.pcap")
    #a.pcapload(filename="tcp6.pcap")

    #turn networking off so that we will dump all packets, and they wont get wrote to the live internet
    #a.networkoff()

    #build an HTTP session
    #build_http(a)

    #build http session using the raw way (meant for other protocols as well)
    #this can work for POP/SMTP/etc
    #other_build_http(a)

    #iterate 30 times AS_perform() (pushes packets to outgoing queue, etc)
    #You can loop this and it would go on forever...right now the app can be used perfectly.
    perform(a,10)

    # how many packets did that generate?
    print("Network Queue Count before dumping PCAP: %d") % a.networkcount()

    #pcap saving to open it in wireshark
    a.pcapsave("py_output.pcap")

    #could turn network dumping on...
    #a.networkon()

    #and loop for awhile...?
    #just be sure the counts are high enoough for each attack structure...
    #perform(a,99999) or (a,0) forever...

    # disable all tasks which happen from perform, and network flushing..
    #a.disable()

    # re-activate everything...
    #a.enable() 

    # do we wish to make the system continue executing? calling our perform()?
    script_enable(a)

    #a.traceroutequeue(target="8.8.8.8")
    #cnt = a.traceroutecount(disabled=0)
    #print("count %d") % cnt
    #if (cnt == 0):
    #    top_sites_research(a)

    return 1
    



# The script can do whatever it needs to generate specific HTTP session bodies relating to a specific site, category, country,
# and whatever other decisions...
def content_generator(language,site_id,site_category,ip_src,ip_dst,ip_src_geo,ip_dst_geo,client_body,client_body_size,server_body,server_body_size):
    server_body = open("server_body", 'rU').read()
    client_body = open("client_body", 'rU').read()

    return client_body, server_body