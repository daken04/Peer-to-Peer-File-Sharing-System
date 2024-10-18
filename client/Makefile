CC = g++
CFLAGS = -Wall -I/opt/homebrew/Cellar/openssl@3/3.3.2/include
LDFLAGS = -L/opt/homebrew/Cellar/openssl@3/3.3.2/lib -lssl -lcrypto -pthread
DEPS = client_header.h
OBJ = client.o calcSHA.o commands.o peerToPeer.o uploadAndDownload.o utilities.o

%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

client: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o client
