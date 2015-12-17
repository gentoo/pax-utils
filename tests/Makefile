SUBDIRS = $(patsubst %/Makefile,%,$(wildcard */Makefile))
abs_top_srcdir = $(realpath $(PWD)/..)
abs_top_builddir = $(realpath $(PWD)/..)
# DO NOT STARE AT THE SUN
all:
%:; $(MAKE) `printf '%s_$@_ ' $(SUBDIRS)`
_words = $(subst _, ,$1)
_dir = $(firstword $(call _words,$@))
_targ = $(lastword $(call _words,$@))
%_:; $(MAKE) -C $(_dir) $(_targ) srcdir=$(abs_top_srcdir)/tests/$(_dir) builddir=$(abs_top_builddir)/tests/$(_dir)
