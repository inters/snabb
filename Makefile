LUASRC = $(wildcard src/lua/*.lua)
LUAOBJ = $(LUASRC:.lua=.o)
CSRC   = $(wildcard src/c/*.c)
COBJ   = $(CSRC:.c=.o)
PREFIX = /usr/local
RECIPE ?= Makefile.vita-test

LUAJIT_CFLAGS := -include $(CURDIR)/gcc-preinclude.h -DLUAJIT_VMPROFILE

all: $(LUAJIT) $(SYSCALL) $(PFLUA) luajit ljsyscall pflua ljndpi libsodium
	cd src && $(MAKE) -f $(RECIPE)
luajit: $(LUAJIT)
	@(cd lib/luajit && (cd src && $(MAKE) reusevm) && $(MAKE) CFLAGS="$(LUAJIT_CFLAGS)")
ljsyscall: $(SYSCALL)
	@mkdir -p src/syscall/linux
	@cp -p lib/ljsyscall/syscall.lua   src/
	@cp -p lib/ljsyscall/syscall/*.lua src/syscall/
	@cp -p  lib/ljsyscall/syscall/linux/*.lua src/syscall/linux/
	@cp -pr lib/ljsyscall/syscall/linux/x64   src/syscall/linux/
	@cp -pr lib/ljsyscall/syscall/shared      src/syscall/
pflua:
	@cp -p lib/pflua/src/pf.lua src/
	@cp -pr lib/pflua/src/pf src/pf
ljndpi:
	@mkdir -p src/ndpi
	@cp -p lib/ljndpi/ndpi.lua src/
	@cp -p lib/ljndpi/ndpi/*.lua src/ndpi/
libsodium:
	@(cd lib/libsodium && ./configure && $(MAKE))

install: all
	install -D src/snabb ${DESTDIR}${PREFIX}/bin/snabb

clean:
	(cd lib/luajit && $(MAKE) clean)
	(cd lib/libsodium && $(MAKE) clean || true)
	(cd src; $(MAKE) clean)
	(cd src; rm -rf syscall.lua syscall ndpi.lua ndpi pf.lua pf)

PACKAGE:=snabbswitch
DIST_BINARY:=snabb
BUILDDIR:=$(shell pwd)

dist: DISTDIR:=$(BUILDDIR)/$(PACKAGE)-$(shell git describe --tags)
dist: all
	mkdir "$(DISTDIR)"
	git clone "$(BUILDDIR)" "$(DISTDIR)/snabbswitch"
	rm -rf "$(DISTDIR)/snabbswitch/.git"
	cp "$(BUILDDIR)/src/snabb" "$(DISTDIR)/"
	if test "$(DIST_BINARY)" != "snabb"; then ln -s "snabb" "$(DISTDIR)/$(DIST_BINARY)"; fi
	cd "$(DISTDIR)/.." && tar cJvf "`basename '$(DISTDIR)'`.tar.xz" "`basename '$(DISTDIR)'`"
	rm -rf "$(DISTDIR)"

docker:
	docker build -t snabb .
	@ln -sf ../src/scripts/dock.sh src/snabb
	@echo "Usage: docker run -ti --rm snabb <program> ..."
	@echo "or simply call 'src/snabb <program> ...'"
.SERIAL: all
.PHONY: luajit ljsyscall pflua ljndpi libsodium
