# Sample application using TSDuck as a library: Makefile for UNIX systems.
#
# The TSDuck development package must have been installed.
#
# By default, the sample application is built against the TSDuck dynamic
# library in /usr/bin. Define TS_STATIC to link against the TSDuck static
# library: make TS_STATIC=true
#
# If you have installed TSDuck in some non-standard location, just use:
# make SYSPREFIX=$HOME/test

# TSDuck definitions are in /usr on Linux and /usr/local on Mac.
SYSPREFIX ?= $(if $(subst Darwin,,$(shell uname -s)),/usr,/usr/local)
include $(SYSPREFIX)/include/tsduck/tsduck.mk

default: myexec

clean:
	@rm -rf *.o *.ts
distclean: clean
	@rm -rf myexec
