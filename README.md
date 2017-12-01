# antisurveillance

This is what a fully automated, no need to upgrade, long term attack on mass surveillance platforms looks like.  It has everyting required to force more resources
than actionable intelligence for each listener node.  The fun part about it is that these "smart attack paths" if performed online will possibly affect dozens of
separate mass surveillance platforms simultaneously.  Its quite magnificiant that the same technology which allows for mass capture of the data in the first place
will also allow anyone to attack worldwide platforms back to back while spoofing packets in a particular manner.  If you believe that this isn't a big deal then
you aren't someone I care about understanding anyhow.  If you are someone who understands all of the layers, and internals of processing the information then you
already know that this is not a game.  This is the result of my personal issues with the US government, and knowing that when the government allows people
to hide under its veil that it takes something extreme such as this to ensure that they don't just move on without performing the proper duties required
in a democracy.  If I firmly believed the actions of these massively corrupt government officials were legitamate in any way shape or form then as an
American I would have never considered designing this in the first place.  However, that kind of situation is a reality far from the truth.


The main subsystems are relatively simple.  It had loops which can call a python script each iteration, for instance a second, for modifications during
exeution.  Traceroute is a subsystem which is designed to create virtual paths between Internet nodes, and the attacking system as well.  It allows precise
calculations of expected mass surveillance damages.  It allows targeting specific Internet fiber cable taps such as the ones Snowden leaked between America,
and Europe.  It can allow you to target any particular tap if you  have a concept of where they are.  It was not until I begain designing, and testing that
I realized the horrible truth.  If you are in America such as where my IP had lay when I developed this technology then you could affect literally dozens
of taps while forcing spoofed packets across the Internet to a country such as China.  It is possible it would go directly from Los Angeles to China although
armed with traceroute, and some understand then you may begin to get the real nightmare-ish picture.  The real nightmare is the fact that all of our data
when routed across the Internet has been picked up by these probable dozen different ISP taps on its way including passwords, etc if those networks were 
located in those areas.  The majority of the major sites will be fairly close for a lot of Internet traffic however DNS which responds different by
various addresses allows you to force various routes on purpose to ensure you reach these other surveillance platforms.

A different subsystem is live packet monitoring which will find HTTP sessions less than 1megabyte, and quicker than 10 seconods with ability to integrate
directly into an attack structure.  The structure will allow replaying possibly infinite times with small changes with the entire purpose of injecting
falsified sessions into X-Keyscore, etc.  It will also allow this tool to be used for other purposes unrelated.  Packet building features for IPv4, and IPv6
are another subsystem which was required to modify the TCP/IP parameters for each replayed attack.  Embedding python scripts for control commands, and now
callbacks to modify content, and soon identities being used in the various attacks was another addition to ensure that I don't have to release more than
a single version  of this tool.  I wanted to ensure a teenage hacker with a lot of time on his hands who barely understands Visual Basic could launch
these attacks if chosen.

Detailed reasoning is in the why directly but it comes down to US government drugging me, raping me, and having zero accountability for their actions.  It
is by far from the last thing I am willing to do to ensure they change their ways quickly.  This is a demonstration.  I have worse things I can  release
which take a lot less code.  I had already released papers regarding the attacks themselves therefore building it was the logical next step.  I understand
that the papars were vague in comparison.  You can read them yourselves in the repository.  I must say whoever thought they were  in control, in charge,
and could continue to do whatever they wanted to me in my life... are fucking morons.  I will do whatever it takes to  ruin you.  I'm really not fucking
with you people.

NSA: nice little video for you guys https://www.youtube.com/watch?v=L-bvse-sM7Q


I'll design some example documentation ready preparing for the first release.  I'm a week behind schedule which isn't too bad.  I plan on releasing a network
0-day which will cause ruckus for several years possibly.  I needed all of these subsystems to increase probability of the attack being successful
without any internal information of networks being attacked.  Thus, traceroute was a stone for two birds as it was designed.

Enjoy the code.

Mike Guidry
Unified Defense Technologies, Inc
Dec 1, 2017
It so happens this company UDT was just disbanded in Florida by the government since I did not send in some yearly report.  I decided that since I wrote the
papers under the corporate 'entity' then I should just continue because a lot of what this government does is try to hide behind different shields such as
military, or corporate to ensure that these people cannot be directly held accountable as individuals.  .. I don't plan on taking any of you to court.  Please
do not go to jail.  I'll be seeing each and every one of you.. :)  Believe I have empty threats?

--------------------------------------- 





this is a version which is controlled by a python script.  It allows easily manipulating, controlling, and using this tool.

This was really to prove a point, and be a demonstration of what will happen if these morons dont get
their shit together.  It seems to be exactly what I thought  it'd be when I begain... I'll claim
a release within 2 days.
11/30/17

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


funny enough.. US intelligencce agencies forfeiting damages of mass surveillance to allow a few morons to decide to keep drugging me
is beyond me... and that alone will force me to lobby, and destroy everyone involved until they are all out of government anyways.

it doesn't matter what happens... everyone involved is done.  trust me.
