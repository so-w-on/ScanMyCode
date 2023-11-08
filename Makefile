CC = gcc
CFLAGS = -Wall -I./include  # Include any necessary directories here

SRCDIR = src
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SOURCES:.c=.o)

all: scanthycode

scanthycode: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SRCDIR)/*.o scanthycode