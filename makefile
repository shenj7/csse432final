client: client.o
	gcc client.o -o client

client.o: client.c
	gcc client.c -c

server: server.o
	gcc server.o -o server

server.o: server.c
	gcc server.c -c
