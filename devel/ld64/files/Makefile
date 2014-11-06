## hardcoded Makefile that simply copies the exact commands I have been
## using to build and test machocheck

all: machocheck.dSYM

src/other/machochecker.o: src/other/machochecker.cpp machocheck_Makefile
	/usr/bin/g++-4.2 -mmacosx-version-min=10.6 -Wno-system-headers -Wall -Wextra -Wno-unused-parameter -Wmissing-include-dirs -Winvalid-pch -Wimplicit -Wconversion -Wshorten-64-to-32 -Wpointer-arith -Wwrite-strings -Wmissing-noreturn -Wformat=2 -Winline -Wswitch -Wswitch-default -Wredundant-decls -Wshadow -mfix-and-continue -gdwarf-2 -ggdb3 -gfull -ftrapping-math -fsignaling-nans -fbounds-check -fstack-check -ftrapv -fstack-protector -ftracer -fmudflapir -O0 -arch x86_64 -arch i386 -I/opt/local/libexec/llvm-3.4/include -D__STRICT_BSD__ -DDEBUG -DLTO_SUPPORT -I/opt/local/var/macports/build/_opt_local_var_macports_sources_rsync.macports.org_release_tarballs_ports_devel_ld64/ld64/work/ld64-136/src/abstraction -I/opt/local/var/macports/build/_opt_local_var_macports_sources_rsync.macports.org_release_tarballs_ports_devel_ld64/ld64/work/ld64-136/src/ld -I/opt/local/var/macports/build/_opt_local_var_macports_sources_rsync.macports.org_release_tarballs_ports_devel_ld64/ld64/work/ld64-136/src/ld/parsers -I/opt/local/include  -c -o $@ $<

machocheck: src/other/machochecker.o
	/usr/bin/g++-4.2 -mmacosx-version-min=10.6 -L/opt/local/lib -Wl,-no_dead_strip_inits_and_terms -Wl,-headerpad_max_install_names -Wl,-warn_compact_unwind -Wl,-warn_stabs -Wl,-warn_commons -Wl,-prebind -arch x86_64 -arch i386 $< -o $@

machocheck.dSYM: machocheck
	dsymutil $<
