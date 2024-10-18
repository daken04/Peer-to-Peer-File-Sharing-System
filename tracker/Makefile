CC = g++
CFLAGS = -Wall -I/opt/homebrew/Cellar/openssl@3/3.3.2/include
DEPS = tracker_header.h
OBJ = tracker.o commands.o utilities.o
%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

tracker: $(OBJ)
	$(CC) $(CFLAGS) -pthread -o $@ $^ 

clean:
	rm -rf *o tracker