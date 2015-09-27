SOURCES := $(shell echo ./*.c)
OBJECTS = $(SOURCES:.c=.o)

srcs: $(SOURCES) $(OBJECTS)

.c.o:
	$(CC) $(CFLAGS) $< -o $(OBJDIR)/$@
