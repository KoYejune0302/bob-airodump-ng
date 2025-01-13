CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

all: airodump

airodump: airodump.c airodump.h
	$(CC) $(CFLAGS) -o airodump airodump.c $(LDFLAGS)

clean:
	rm -f airodump