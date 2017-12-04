CC=gcc
CFLAGS=-I. -ggdb -Wall -I/usr/include/python2.7_d -I/usr/include/x86_64-linux-gnu/python2.7_d  -fno-strict-aliasing -Wdate-time -g -O0 -fstack-protector-strong -Wformat -Werror=format-security -g -O0 -Wall -Wstrict-prototypes -I/home/mike/antisurveillance/deps/geoip-api-c/libGeoIP -Ideps/http-parser

DEPS = antisurveillance.h
ODIR=obj
LIBS=-lz -lpthread -ggdb -lpython2.7_d -lpthread -ldl  -lutil -lm   -L/usr/lib -lpython2.7_d -lpthread -ldl  -lutil -lm  -Xlinker -export-dynamic -Wl,-O1 -Wl,-Bsymbolic-functions -L/home/mike/antisurveillance/deps/geoip-api-c/libGeoIP/.libs -lGeoIP




_OBJ = packetbuilding.o pcap.o antisurveillance.o network.o  adjust.o  instructions.o  http.o  research.o  utils.o  scripting.o  attacks.o  identities.o macro.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS) scriptmain.o cmdline.o
	$(CC) -static -c -o $@ $< $(CFLAGS)

pyanti: $(OBJ) obj/scriptmain.o 
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

tracedev: $(OBJ) obj/tracedev.o
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

anti: $(OBJ) obj/cmdline.o
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

anti_static: $(OBJ) cmdline.o
	gcc -static -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f anti $(ODIR)/*.o *~ core $(INCDIR)/*~ 

all: clean anti pyanti tracedev
