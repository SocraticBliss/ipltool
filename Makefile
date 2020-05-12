CPP=gcc
CPPFLAGS= -Wall -g -O0 -std=c99 -Iinclude
LDFLAGS=
SOURCES=src/amctrl.c src/aes.c src/crypto.c src/ec.c src/ec_ipltool.c src/kirk_engine.c src/ipltool.c src/sha1.c src/utils.c
EXECUTABLE=ipltool

all:
	$(CPP) $(CPPFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)
