CC=gcc
CFLAGS=-I. -ggdb -Wall
DEPS = antisurveillance.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

anti: os_emulation.o packetbuilding.o pcap.o antisurveillance.o network.o  adjust.o  instructions.o  http.o  research.o  utils.o  scripting.o  attacks.o
	gcc -o anti os_emulation.o packetbuilding.o pcap.o antisurveillance.o network.o  adjust.o  instructions.o  http.o  research.o  utils.o  scripting.o  attacks.o  -lz -lpthread picohttpparser.c -ggdb

clean:
	rm -f anti *.o
