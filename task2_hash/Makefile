CC        = g++
CFLAGS    = -Wall -lcrypto 

TARGETS   = lab2
lab2: lab2.cpp
	$(CC) $< $(CFLAGS) -o $@ 
run:
	./$(TARGETS) 4
clean:
	\rm -f $(TARGETS) *~ core

