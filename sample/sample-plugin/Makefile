# Sample TSDuck plugin: Makefile for UNIX systems.
# The TSDuck development package must have been installed.

# TSDuck definitions are in /usr on Linux and /usr/local on Mac.
SYSPREFIX ?= $(if $(subst Darwin,,$(shell uname -s)),/usr,/usr/local)
include $(SYSPREFIX)/include/tsduck/tsduck.mk

# Default installation directory prefix.
# RPM packagers should override this in the "make install" command line.
DESTDIR :=

# All plugin shared libraries from this directory.
SHLIBS := $(addsuffix .so,$(basename $(wildcard tsplugin_*.cpp)))

# Compilation rules for shared libraries.
%.so: %.o
	$(CC) $(CFLAGS) $(SOFLAGS) $(LDFLAGS) $^ $(LDLIBS) -shared -o $@

# Local compilation flags (-fPIC for shared objects).
CXXFLAGS += -fPIC

# Main target: build all plugins here.
default: $(SHLIBS)
	@true

clean distclean:
	@rm -rf *.o *.so

.PHONY: install
install: $(SHLIBS)
	install -d -m 755 $(DESTDIR)$(TS_PLUGIN_DIR)
	install -m 755 $(SHLIBS) $(DESTDIR)$(TS_PLUGIN_DIR)
