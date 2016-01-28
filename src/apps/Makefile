UMQTT_PUB_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_client.o \
                 $(OBJDIR)/uMQTT_linux_client.o \
                 $(OBJDIR)/uMQTT_helper.o

UMQTT_SUB_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_client.o \
                 $(OBJDIR)/uMQTT_linux_client.o \
                 $(OBJDIR)/uMQTT_helper.o

apps: uMQTT_pub
apps: uMQTT_sub

uMQTT_pub:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_PUB_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@


uMQTT_sub:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_SUB_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

