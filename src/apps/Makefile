UMQTT_PUB_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_client.o \
                 $(OBJDIR)/uMQTT_linux_client.o \
                 $(OBJDIR)/uMQTT_helper.o \
                 $(OBJDIR)/log.o

UMQTT_SUB_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_client.o \
                 $(OBJDIR)/uMQTT_linux_client.o \
                 $(OBJDIR)/uMQTT_helper.o \
                 $(OBJDIR)/log.o

UMQTT_PRINT_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_helper.o \
                 $(OBJDIR)/log.o

UMQTT_GEN_PKT_OBJS = $(OBJDIR)/uMQTT.o $(OBJDIR)/uMQTT_helper.o \
                 $(OBJDIR)/log.o

apps: uMQTT_pub
apps: uMQTT_sub
apps: uMQTT_print_packet
apps: uMQTT_gen_pkt

uMQTT_pub:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_PUB_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

uMQTT_sub:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_SUB_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

uMQTT_print_packet:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_PRINT_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@

uMQTT_gen_pkt:
	$(CC) $(CFLAGS) $@.c -o $(OBJDIR)/$@.o
	$(CC) $(LDFLAGS) $(UMQTT_GEN_PKT_OBJS) $(OBJDIR)/$@.o -o $(BINDIR)/$@
