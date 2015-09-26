CC = gcc
CFLAGS = -c -Wall -Werror
LDFLAGS =


EXE = umqtt
TEST_EXE = umqtt_tests

tests: SRCS = uMQTT_utests.c uMQTT.c
tests: EXE = umqtt_tests
tests: OBJS = $(call OBJ $(SRCS))

all: SRCS = uMQTT_client_test.c uMQTT_client.c uMQTT.c
all: EXE = umqtt


all tests: $(SRCS) $(EXE)
	
OBJ = $(SRCS:.c=.o)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $@

clean:
	rm -f *.o $(EXE) $(TEST_EXE)

.PHONY: all
