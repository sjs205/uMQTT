SRCDIR = $(CURDIR)/src
BINDIR = $(CURDIR)/bin
OBJDIR = $(BINDIR)/obj
SRCDIR = $(CURDIR)/src
INCDIR = $(SRCDIR)/inc

TARGET = x86

ifeq ($(TARGET),x86)
	CC = gcc
	CFLAGS = -c -Wall -Werror -I$(INCDIR) -g3 -O0
	LDFLAGS =
else ifeq ($(TARGET),avr)
	CC = avr-gcc
	CFLAGS = -c -Wall -Werror -I$(INCDIR)
	LDFLAGS =
endif

MKDIR_P = mkdir -p

export

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

.PHONY: clean
clean:
	rm -rf $(BINDIR)
