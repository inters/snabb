Q= @
E= @echo
# For verbose command line output, uncomment these lines:
#Q=
#E= @:

export TEST_SKIPPED=43
CC ?= gcc

# This variable lists all paths included in the build and can be narrowed down
# if you want it to be limited to certain paths. For instance
#   INCLUDE=./*.* ./core
# would build a very limited "core" Snabb.
INCLUDE ?= *

SRCDIR = $(shell find . -type d -not -regex './obj.*' -printf '%P ')
OBJDIR = $(patsubst %,obj/%,$(SRCDIR))

LUASRC = $(shell find $(INCLUDE) -regex '[^\#]*\.lua' -printf '%p ')
CSRC   = $(shell find $(INCLUDE) -regex '[^\#]*\.c' -not -regex 'arch/.*' -printf '%p ')
CHDR   = $(shell find $(INCLUDE) -regex '[^\#]*\.h' -printf '%p ')
ASM    = $(shell find $(INCLUDE) -regex '[^\#]*\.dasl' -printf '%p ')
ARCHSRC= $(shell find $(INCLUDE) -regex 'arch/[^\#]*\.c' -printf '%p ')
RMSRC  = $(shell find $(INCLUDE) -name '*.md' -not -regex './obj.*' -printf '%p ')
# regexp is to include program/foo but not program/foo/bar
PROGRAM = $(shell find program -regex '^[^/]+/[^/]+' -type d -printf '%p ')
# sort to eliminate potential duplicate of programs.inc
INCSRC = $(sort $(shell find $(INCLUDE) -regex '[^\#]*\.inc' -printf '%p ') programs.inc)
EVTSRC= $(shell find $(INCLUDE) -regex '[^\#]*\.events' -printf '%p ')
YANGSRC= $(shell find $(INCLUDE) -regex '[^\#]*\.yang' -printf '%p ')

LUAOBJ := $(patsubst %.lua,obj/%_lua.o,$(LUASRC))
BLAKEOBJ := $(shell find ../lib/blake/sse -name '*.o' -printf '%p ')
CURVE25519OBJ := $(shell find ../lib/curve25519sandy2x -name '*.o' -printf '%p ')
COBJ   := $(patsubst %.c,obj/%_c.o,    $(CSRC))
HOBJ   := $(patsubst %.h,obj/%_h.o,    $(CHDR))
ARCHOBJ:= $(patsubst %.c,obj/%_c.o,    $(ARCHSRC))
ASMOBJ := $(patsubst %.dasl,obj/%_dasl.o,   $(ASM))
PFLUAASMOBJ := $(patsubst %.dasl,obj/%_dasl.o,   $(PFLUAASM))
JITOBJS:= $(patsubst %,obj/jit_%.o,$(JITSRC))
EXTRAOBJS := obj/jit_tprof.o obj/jit_vmprof.o obj/strict.o
RMOBJS := $(patsubst %,obj/%,$(RMSRC))
INCOBJ := $(patsubst %.inc,obj/%_inc.o, $(INCSRC))
EVTOBJ := $(patsubst %.events,obj/%_events.o, $(EVTSRC))
YANGOBJ:= $(patsubst %.yang,obj/%_yang.o, $(YANGSRC))
EXE    := bin/snabb $(patsubst %,bin/%,$(PROGRAM))

LUAJIT_A := ../lib/luajit/src/raptorjit.a

# TESTMODS expands to:
#   core.memory core.lib ...
# for each module that has a top-level selftest () function.
TESTMODS = $(shell find $(INCLUDE) -regex '[^\#]*\.\(lua\|dasl\)' -printf '%p ' | \
             xargs grep -s -l '^function selftest *[[:punct:]]' | \
             sed -e 's_\.lua__' -e 's_\.dasl__' -e 's_/_._g' -e 's/-/_/g')

# TESTSCRIPTS expands to:
#   lib/watchdog/selftest.sh ...
# for each executable selftext.* script in src.
TESTSCRIPTS = $(shell find $(INCLUDE) -name "selftest.*" -executable | xargs)

PATH := ../lib/luajit/src:$(PATH)

snabb: $(LUAOBJ) $(PFLUAOBJ) $(HOBJ) $(COBJ) $(ARCHOBJ) $(ASMOBJ) $(PFLUAASMOBJ) $(INCOBJ) $(EVTOBJ) $(YANGOBJ) $(LUAJIT_A)
	$(E) "GEN       obj/version.lua.gen"
	$(Q) ../generate-version-lua.sh > obj/version.lua.gen
	$(E) "LUA       obj/version.lua"
	$(Q) raptorjit -bg -n core.version obj/version.lua.gen obj/version_lua.o
	$(E) "LINK      $@"
	$(Q) $(CC) $(DEBUG) -Wl,--no-as-needed -Wl,-E -Werror -Wall -o $@ $^ \
	    obj/version_lua.o \
	    $(BLAKEOBJ) $(CURVE25519OBJ) -no-pie \
	    -lrt -lc -ldl -lm -lpthread
	@echo -n "BINARY    "
	@ls -sh snabb

all: $(EXE)

# Rebuild after git submodules are updated.
submods:
	(cd ..; git submodule update; make clean; make)

$(EXE): snabb bin
	$(E) "COMPRESS  $@"
	$(Q) upx -f --brute -o$@ snabb
	@echo -n "BINARY    "
	@ls -sh $@

markdown: $(RMOBJS)

test: $(TESTMODS) $(TESTSCRIPTS)

test_ci: FAIL_ON_FIRST="true"

test_ci: $(TESTMODS) $(TESTSCRIPTS)

$(TESTMODS): testlog snabb
	$(E) "TEST      $@"
	$(Q) ./snabb snsh -t $@ > testlog/$@ 2>&1 || ( \
		EXITCODE="$$?"; \
		[ "$$EXITCODE" -eq $(TEST_SKIPPED) ] \
		&& ( \
			echo "SKIPPED   testlog/$@"; \
			echo "EXITCODE: $$EXITCODE" >> testlog/$@; \
		) \
		|| ( \
			echo "ERROR     testlog/$@"; \
			echo "EXITCODE: $$EXITCODE" >> testlog/$@; \
			if [ -n "$(FAIL_ON_FIRST)" ]; then exit $$EXITCODE; fi;\
		) \
	)

testlog = testlog/$(shell echo "$(@)" | sed -e 's_/_._g')
$(TESTSCRIPTS): testlog snabb
	$(E) "TEST      $@"
	$(Q) ./$@ > $(testlog) 2>&1 || ( \
		EXITCODE="$$?"; \
		[ "$$EXITCODE" -eq $(TEST_SKIPPED) ] \
		&& ( \
			echo "SKIPPED   $(testlog)"; \
			echo "EXITCODE: $$EXITCODE" >> $(testlog); \
		) \
		|| ( \
			echo "ERROR     $(testlog)"; \
			echo "EXITCODE: $$EXITCODE" >> $(testlog); \
			if [ -n "$(FAIL_ON_FIRST)" ]; then exit $$EXITCODE; fi;\
		) \
	)

$(OBJDIR) bin testlog $(OBJDIR/doc):
	$(E) "DIR       $@"
	$(Q) mkdir -p $@

$(LUAOBJ): obj/%_lua.o: %.lua Makefile | $(OBJDIR)
	$(E) "LUA       $@"
	$(Q) raptorjit -bg -n $(subst /,.,$*) $< $@

$(PFLUAOBJ): obj/%_lua.o: ../lib/pflua/src/%.lua Makefile
	$(E) "LUA       $@"
	$(Q) mkdir -p $(dir $@)
	$(Q) raptorjit -bg -n $(subst /,.,$*) $< $@

$(COBJ): obj/%_c.o: %.c $(CHDR) Makefile | $(OBJDIR)
	$(E) "C         $@"
	$(Q) $(CC) $(DEBUG) -O3 -Wl,-E -I ../lib/luajit/src -I . -include $(CURDIR)/../gcc-preinclude.h -c -Wall -Werror -o $@ $<

obj/arch/avx2_c.o: arch/avx2.c Makefile
	$(E) "C(AVX2)   $@"
	$(Q) $(CC) -O2 -mavx2 $(DEBUG) -Wl,-E -I ../lib/luajit/src -I . -include $(CURDIR)/../gcc-preinclude.h -c -Wall -Werror -o $@ $<

obj/arch/sse2_c.o: arch/sse2.c Makefile
	$(E) "C(SSE2)   $@"
	$(Q) $(CC) -O2 -msse2 $(DEBUG) -Wl,-E -I ../lib/luajit/src -I . -include $(CURDIR)/../gcc-preinclude.h -c -Wall -Werror -o $@ $<

$(HOBJ): obj/%_h.o: %.h Makefile | $(OBJDIR)
	$(E) "H         $@"
	@(echo -n "module(...,package.seeall); require(\"ffi\").cdef[=============["; \
	 cat $<; \
	 echo "]=============]") > $(basename $@).luah
	$(Q) raptorjit -bg -n $(subst /,.,$*)_h $(basename $@).luah $@

$(ASMOBJ): obj/%_dasl.o: %.dasl $(CHDR) Makefile | $(OBJDIR)
	$(E) "ASM       $@"
	$(Q) raptorjit dynasm.lua -o $@.gen $<
	$(Q) raptorjit -bg -n $(subst /,.,$*) $@.gen $@

$(PFLUAASMOBJ): obj/%_dasl.o: ../lib/pflua/src/%.dasl $(CHDR) Makefile | $(OBJDIR)
	$(E) "ASM       $@"
	$(Q) mkdir -p $(dir $@)
	$(Q) raptorjit dynasm.lua -o $@.gen $<
	$(Q) raptorjit -bg -n $(subst /,.,$*) $@.gen $@

$(JITOBJS): obj/jit_%.o: ../lib/luajit/src/jit/%.lua $(OBJDIR)
	$(E) "LUA       $@"
	$(Q) raptorjit -bg -n $(patsubst obj/jit_%.o, jit.%, $@) $< $@

$(RMOBJS): obj/%: %
	$(E) "MARKDOWN  $@"
	$(Q) scripts/process-markdown $< $@

$(INCOBJ): obj/%_inc.o: %.inc Makefile | $(OBJDIR)
	$(E) "INC       $@"
	@(echo -n "return [=============["; \
	 cat $<; \
	 echo "]=============]") > $(basename $@).luainc
	$(Q) raptorjit -bg -n $(subst /,.,$*)_inc $(basename $@).luainc $@

$(EVTOBJ): obj/%_events.o: %.events Makefile | $(OBJDIR)
	$(E) "EVENTS    $@"
	@(echo -n "return [=============["; \
	 cat $<; \
	 echo "]=============]") > $(basename $@).luainc
	$(Q) raptorjit -bg -n $(subst /,.,$*)_events $(basename $@).luainc $@

$(YANGOBJ): obj/%_yang.o: %.yang Makefile | $(OBJDIR)
	$(E) "YANG      $@"
	@(echo -n "return [=============["; \
	 cat $<; \
	 echo "]=============]") > $(basename $@).luayang
	$(Q) raptorjit -bg -n $(subst /,.,$*)_yang $(basename $@).luayang $@

# Create list of programs that exist
programs.inc: program
	@(for d in `find $(INCLUDE) -regex '[^\#]*' | grep -E '^program/[^/]*$$'`; do basename $$d; done) > $@

FORCE:

# extra/ third party bits and pieces
obj/strict.o: extra/strict.lua | $(OBJDIR)
	$(E) "LUA       $@"
	$(Q) raptorjit -bg $< $@

obj/jit_tprof.o: extra/tprof.lua | $(OBJDIR)
	$(E) "LUA       $@"
	$(Q) raptorjit -bg -n jit.tprof $< $@

obj/jit_vmprof.o: extra/vmprof.c | $(OBJDIR)
	$(E) "C         $@"
	$(Q) $(CC) $(DEBUG) -Wl,-E -O2 -I ../lib/luajit/src -c -Wall -Werror -o $@ $<

book: obj/doc/snabb.pdf obj/doc/snabb.html obj/doc/snabb.epub

obj/doc/snabb.markdown: markdown Makefile doc/genbook.sh
	(cd doc; ./genbook.sh) > $@

obj/doc/snabb.pdf: obj/doc/snabb.markdown
	$(E) "PANDOC    $@"
	$(Q) (cd obj/doc; pandoc --template=../../doc/template.latex --latex-engine=lualatex -V fontsize=10pt -V monofont=droidsansmono -V monoscale=.70 -V verbatimspacing=.85 -V mainfont=droidserif -V sansfont=droidsans -V documentclass:book -V geometry:top=1.0in -V geometry:bottom=0.75in -S --toc --chapters  -o ../../$@ ../../$<)

obj/doc/snabb.html: obj/doc/snabb.markdown
	$(E) "PANDOC    $@"
	$(Q) (cd obj/doc; pandoc --self-contained --css="../../doc/style.css" -S -s --toc --chapters -o ../../$@ ../../$<)

obj/doc/snabb.epub: obj/doc/snabb.markdown
	$(E) "PANDOC    $@"
	$(Q) (cd obj/doc; pandoc --self-contained --css="../../doc/style.css" -S -s --toc --chapters -o ../../$@ ../../$<)

CLEAN = snabb obj bin testlog programs.inc

clean_programs:
	@(for d in program/*/; do \
		if [ -f "$$d/Makefile" ]; then \
			echo "CLEAN     $$d"; \
			make -s -C $$d clean; \
		fi \
	  done)

clean: clean_programs
	$(E) "RM        $(CLEAN)"
	$(Q)-rm -rf $(CLEAN)

mrproper: clean
	$(E) "RM        $(RMOBJS)"
	$(Q)-rm -rf $(RMOBJS)

benchmarks:
	$(Q) (scripts/bench.sh)

.PHONY: clean_programs clean $(TESTMODS) $(TESTSCRIPTS) benchmarks
