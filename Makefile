include config.mk


ifdef DEBUG
	CFLAGS += -UNDEBUG -g -O0
else
	CFLAGS += -DNDEBUG=1 -O3
endif

LDFLAGS += -ludns

UDNS_OBJ := udns/mod_udns.o


.PHONY: all clean test

all: udns/_udns.so

udns/mod_udns.o: udns/mod_udns.h
	$(CC) -pthread -fPIC $(shell $(PYTHON)-config --cflags) $(CFLAGS) -c udns/mod_udns.c -o udns/mod_udns.o

udns/_udns.so: $(UDNS_OBJ)
	-#$(PYTHON) setup.py build_ext -fgb .
	$(CC) -pthread -shared -Wl,-Bsymbolic-functions $(LDFLAGS) $(UDNS_OBJ) -ludns -o $@

clean:
	-rm -f udns/mod_udns.o
	-rm -f udns/_udns.so
	-rm -rf build

test: udns/_udns.so
	$(PYTHON) test.py
