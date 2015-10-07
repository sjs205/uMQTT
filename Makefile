SRCDIR = $(CURDIR)/src
BINDIR = $(CURDIR)/bin
OBJDIR = $(BINDIR)/obj
SRCDIR = $(CURDIR)/src
INCDIR = $(SRCDIR)/inc
AVRDIR = $(SRCDIR)/avr

MKDIR_P = mkdir -p
	
export

PLATFORM = x86

ifeq ($(PLATFORM),x86)

CC = gcc
CFLAGS = -c -Wall -Werror -I$(INCDIR) -O2
LDFLAGS =

else ifeq ($(PLATFORM),avr)

avr: setup
	$(MAKE) -C src/avr/ all

endif

all: setup srcs apps tests

setup:
	${MKDIR_P} ${OBJDIR}

srcs: setup
	$(MAKE) -C src/ srcs

apps: setup srcs
	$(MAKE) -C src/apps apps

tests: setup srcs
	$(MAKE) -C src/tests/ tests

debug: CFLAGS += -DDEBUG -g -O0
debug: all

.PHONY: clean
clean:
	rm -rf $(BINDIR) $(AVRDIR)/*.{elf,eep,lss,map,o,lst,sym,hex}
