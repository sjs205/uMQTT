UMQTT_PUB_TEST_OBJS = $(OBJDIR)/uMQTT_client.o \
                      $(OBJDIR)/uMQTT.o \
                      $(OBJDIR)/uMQTT_linux_client.o \
                      $(OBJDIR)/uMQTT_helper.o \
                      $(OBJDIR)/log.o

UMQTT_SUB_TEST_OBJS = $(OBJDIR)/uMQTT_client.o \
                      $(OBJDIR)/uMQTT.o \
                      $(OBJDIR)/uMQTT_linux_client.o \
                      $(OBJDIR)/uMQTT_helper.o \
                      $(OBJDIR)/log.o

UMQTT_UTEST_OBJS = $(OBJDIR)/uMQTT_client.o \
                   $(OBJDIR)/uMQTT.o \
                   $(OBJDIR)/uMQTT_helper.o \
                   $(OBJDIR)/log.o

UMQTT_PRINT_PKTS_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_helper.o \
                        $(OBJDIR)/log.o

tests: uMQTT_pub_test uMQTT_sub_test uMQTT_tests uMQTT_print_packets

uMQTT_pub_test:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_PUB_TEST_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

uMQTT_sub_test:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_SUB_TEST_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

uMQTT_tests:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_UTEST_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

uMQTT_print_packets:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_PRINT_PKTS_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

