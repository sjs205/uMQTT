SRCDIR = $(CURDIR)/src
BINDIR = $(CURDIR)/bin
OBJDIR = $(BINDIR)/obj
LIBDIR = $(CURDIR)/lib
SRCDIR = $(CURDIR)/src
INCDIR = $(SRCDIR)/inc
AVRDIR = $(SRCDIR)/avr

CLEAN=$(BINDIR) $(LIBDIR) $(AVRDIR)/*.{elf,eep,lss,map,o,lst,sym,hex}
CLEAN+=uMQTT_contiki.c uMQTT_contiki.h

MKDIR_P = mkdir -p
	
export

PLATFORM = x86

ifeq ($(PLATFORM),x86)

CC = gcc
CFLAGS += -c -Wall -Werror -I$(INCDIR) -O2
LDFLAGS =

else ifeq ($(PLATFORM),avr)

avr: setup
	$(MAKE) -C src/avr/ all

endif

all: setup srcs apps tests libs

setup:
	${MKDIR_P} ${OBJDIR} $(LIBDIR)

srcs: setup
	$(MAKE) -C src/ srcs

libs: setup libs
	$(MAKE) -C src/ libs

apps: setup srcs
	$(MAKE) -C src/apps apps

tests: setup srcs
	$(MAKE) -C src/tests/ tests

sdcc:
	$(MAKE) -f src/Makefile.sdcc

debug: CFLAGS += -DDEBUG -g -O0
debug: all

.PHONY: clean contiki

contiki:
	cp src/inc/uMQTT.h uMQTT_contiki.h
	sed 's;uMQTT.h;uMQTT_contiki.h;' src/uMQTT.c > uMQTT_contiki.c

clean:
	rm -rf $(CLEAN)
