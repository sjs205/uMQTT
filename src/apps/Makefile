UMQTT_PUB_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_client.o \
                 $(OBJDIR)/uMQTT_linux_client.o

apps: uMQTT_pub

uMQTT_pub:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_PUB_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

