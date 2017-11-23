CC=gcc
CFLAGS=-I. -ggdb -Wall -I/usr/include/python2.7 -I/usr/include/x86_64-linux-gnu/python2.7 
DEPS = antisurveillance.h
ODIR=obj
LIBS=-lz -lpthread -ggdb -lpython2.7 -ldl -lm -lutil

_OBJ = os_emulation.o packetbuilding.o pcap.o antisurveillance.o network.o  adjust.o  instructions.o  http.o  research.o  utils.o  scripting.o  attacks.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS) scriptmain.o cmdline.o
	$(CC) -c -o $@ $< $(CFLAGS)

antiscript: $(OBJ) scriptmain.o
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

anti: $(OBJ) cmdline.o
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

anti_static: $(OBJ) cmdline.o
	gcc -static -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f anti $(ODIR)/*.o *~ core $(INCDIR)/*~ 

all: clean anti antiscript
