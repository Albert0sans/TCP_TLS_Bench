PROG ?= sslecho

all: $(PROG)

# Debug version.
#
$(PROG): main.c

	$(CC) -O0 -g3 -W -Wall -I../../include -L../../ -o $(PROG) main.c utils.c -lssl -lcrypto

clean:
	rm -rf $(PROG) *.o *.obj