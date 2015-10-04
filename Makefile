SRCDIR = $(CURDIR)/src
BINDIR = $(CURDIR)/bin
OBJDIR = $(BINDIR)/obj
SRCDIR = $(CURDIR)/src
INCDIR = $(SRCDIR)/inc

MKDIR_P = mkdir -p

export

PLATFORM = x86

ifeq ($(PLATFORM),x86)
	
CC = gcc
CFLAGS = -c -Wall -Werror -I$(INCDIR) -g3 -O0
LDFLAGS =

all: setup srcs apps tests

setup:
	${MKDIR_P} ${OBJDIR}

srcs: setup
	$(MAKE) -C src/ srcs

apps: setup srcs
	$(MAKE) -C src/apps apps

tests: setup srcs
	$(MAKE) -C src/tests/ tests

debug: CFLAGS += -DDEBUG -g
debug: all

else ifeq ($(PLATFORM),avr)

CC = avr-gcc
CFLAGS = -c -Wall -Werror -I$(INCDIR)
LDFLAGS =

avr: setup
	$(MAKE) -C src/avr/ all

setup:
	${MKDIR_P} ${OBJDIR}

unexport PLATFORM

endif

.PHONY: clean
clean:
	rm -rf $(BINDIR)
