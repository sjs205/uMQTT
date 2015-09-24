CC=gcc
CFLAGS=-c -Wall -Werror
LDFLAGS=
SOURCES= uMQTT_client_test.c uMQTT_client.c uMQTT.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=umqtt

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o $(EXECUTABLE)	
