/*

This will be ready to go cyber warfare portion...

The point of this is to go from 30,000 connections a minute to as many as possible.  I will attempt to make this as small and concise as possible... I'd like it to be
modular enough to work diretly in routers.  It can have the option branching off the packet sending to other boxes keeping things minimum on routers, and it should
work fine.

A lot of the packets can be automatically determined thus only one single SEQ from remote webserver is really required.  One connection to the webserver along with that
seq will give us a roadmap for every following connection of the same request, and if the web server is using PSH which most are... itll send back the entire response.
example:
Seq (or ACK if remote side) increases by the size, and on some TCP/IP flags by one.. the same request will affect the SEQ by the same amount if done equally...
the remote side will send back a full response, and even further packets  regardless of receiving anymore proper SEQs so if the remote side has somme dynamic scrits
such as PHP, etc.. and its SEQ cannot be foreseen.. its already too late and the damage is done.  This is why only a SINGLE SEQ (initial) is required.  The burden
is decreased greatly because of this.  Quantum inserts entire framework could be weaponized worldwide immediately today due to their infrastructure already beign in
place, etc.

Do not fear.  A lot of other companies, ISPs, etc all have networks with passive monitoring that you can hack so you can be a world class cyber warrior as well.

The games are no longer just for the NSA.  I bring you fun.  DDoS 2.0.

Impossible to firewall, impossible to trace... just pure cyber warfare.
*/

// current attacks must be listed somewhere.. lets  have a small list so that we can just initialize connections to the router
// and itll find the proper data when that moment arrives and generate the bytes required to get the full HTTP response back to the client
typedef struct _attack_queue {

}


