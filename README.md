# antisurveillance


pyanti:

this is a version which is controlled by a python script.  It allows easily manipulating, controlling, and using this tool.
it is a work in progress, and being actively developed...



gcc -o anti anti_surveillance.cpp
./anti 1.2.3.4 31337 2.2.2.2 80 client_body server_body 1 1
then open output.pcap in wireshark or tcpdump -r 


if you'd like to test 5000 simultaneous http sessions... do this:
gcc -o anti anti_surveillance.cpp -ggdb -DBIG_TEST
then same command line.. the output will have al different source + destinnation IPs
its fully green in wireshark.. id say this is ready for an attack.


This was a part of another project but I moved it here to attempt to cleanup.  I need to add content generation from external scripts, or software so it was about to get
really messy.

original location:
https://github.com/mikeguidry/clockwork/tree/antisurveillance/modules/anti_surveillance



Funny enough.. It could be turned into a surveillance platform with the correct filters, and some external application preparing to analyze the data... LOL


The base code is pretty tough on these surveillance platforms therefore directly rough on the NSA.  The upcoming code is a cherry, icing, and
lesson to the NSA.  I gave them 3 days.  It isn't the first time I have set an amount of time to stop fucking with my life.  Oh well.  

IDFWU - https://www.youtube.com/watch?v=L-bvse-sM7Q


FYI: this not the last step in ruining mass surveillance.  but you guys do need a break after this.. so you'll ahve a little time while
i move on to other things.

