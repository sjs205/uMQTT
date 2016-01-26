SOURCES := $(shell echo ./*.c)
OBJECTS = $(SOURCES:.c=.o)
LIBS = $(OBJECTS:.o=.a)

srcs: $(SOURCES) $(OBJECTS)
libs: srcs $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $< -o $(OBJDIR)/$@

.o.a:
	$(AR) rcs $(LIBDIR)/lib$@ $(OBJDIR)/$< 
