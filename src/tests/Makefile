CLIENT_TEST_OBJS = $(OBJDIR)/uMQTT_client.o $(OBJDIR)/uMQTT.o
UMQTT_UTEST_OBJS = $(OBJDIR)/uMQTT_client.o $(OBJDIR)/uMQTT.o

tests: uMQTT_client_test uMQTT_tests

uMQTT_client_test:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(CLIENT_TEST_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

uMQTT_tests:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_UTEST_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@
