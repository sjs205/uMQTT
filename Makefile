SRCDIR = $(CURDIR)/src
BINDIR = $(CURDIR)/bin
OBJDIR = $(BINDIR)/obj
SRCDIR = $(CURDIR)/src
INCDIR = $(SRCDIR)/inc

CC = gcc
CFLAGS = -c -Wall -Werror -I$(INCDIR)
LDFLAGS =

MKDIR_P = mkdir -p

export

all: setup srcs tests

setup:
	${MKDIR_P} ${OBJDIR}

srcs: setup
	$(MAKE) -C src/ srcs

tests: srcs setup
	$(MAKE) -C src/tests/ tests

.PHONY: clean
clean:
	rm -rf $(BINDIR)
