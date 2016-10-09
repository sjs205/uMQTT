SRCDIR = $(CURDIR)/src
BINDIR = $(CURDIR)/bin
DOCDIR = $(CURDIR)/docs
OBJDIR = $(BINDIR)/obj
LIBDIR = $(CURDIR)/lib
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

debug: CFLAGS += -DDEBUG -g -O0
debug: all

.PHONY: clean docs
docs:
	doxygen $(DOCDIR)/doxygen.cfg.in

clean:
	rm -rf $(BINDIR) $(LIBDIR) $(AVRDIR)/*.{elf,eep,lss,map,o,lst,sym,hex} \
         $(DOCDIR)/docs $(DOCDIR)/html
