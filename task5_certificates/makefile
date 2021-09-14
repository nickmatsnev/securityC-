CC = g++
FLAGS = -lssl -lcrypto -std=c++11
LIB = -L/usr/local/opt/openssl@1.1/lib
INCL = -I/usr/local/opt/openssl@1.1/include
OBJ = lab5.o

CLIENT = lab5.cpp


all: compile run
	
compile:
	$(CC) $(CLIENT) $(FLAGS) -o $(OBJ);

run:
	./$(OBJ)
clean:
	rm ./*.o ./*.pem ./*.txt
