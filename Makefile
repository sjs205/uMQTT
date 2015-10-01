SRCDIR = $(CURDIR)/src
BINDIR = $(CURDIR)/bin
OBJDIR = $(BINDIR)/obj
SRCDIR = $(CURDIR)/src
INCDIR = $(SRCDIR)/inc

CC = gcc
CFLAGS = -c -Wall -Werror -I$(INCDIR) -g3 -O0
LDFLAGS =

MKDIR_P = mkdir -p

export

all: setup srcs apps tests

setup:
	${MKDIR_P} ${OBJDIR}

srcs: setup
	$(MAKE) -C src/ srcs

apps: setup
	$(MAKE) -C src/apps apps

tests: srcs setup
	$(MAKE) -C src/tests/ tests

.PHONY: clean
clean:
	rm -rf $(BINDIR)
