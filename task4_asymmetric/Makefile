CC = g++
FLAGS = $(STDFLAG) $(LCFLAG) $(LIB) $(INCL)
LCFLAG = -lcrypto
STDFLAG = -std=c++11
LIB = -L/usr/local/opt/openssl@1.1/lib
INCL = -I/usr/local/opt/openssl@1.1/include
OBJ_ENCRYPT = enc.o
OBJ_DECRYPT = decr.o

ENCRYPT = enc.cpp
DECRYPT = dec.cpp

CIPHER = aes-256-cbc

IN = input.txt
OUT = output.txt
OUT_DEC = input_dec.txt

PUB_KEY = pubkey.pem
PRIV_KEY = privkey.pem

all: compile encrypt decrypt compare
	
compile:
	$(CC) $(ENCRYPT) $(FLAGS) -o $(OBJ_ENCRYPT)
	$(CC) $(DECRYPT) $(FLAGS) -o $(OBJ_DECRYPT)

encrypt:
	./$(OBJ_ENCRYPT) $(IN) $(PUB_KEY) $(OUT) $(CIPHER)

decrypt:
	./$(OBJ_DECRYPT)  $(OUT) $(PRIV_KEY) $(OUT_DEC)
compare:
	diff input.txt input_dec.txt


clean:
	rm *.o res*.txt