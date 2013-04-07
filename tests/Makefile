SUBDIRS = $(patsubst %/Makefile,%,$(wildcard */Makefile))
# DO NOT STARE AT THE SUN
all:
%:; $(MAKE) `printf '%s_$@_ ' $(SUBDIRS)`
_words = $(subst _, ,$1)
_dir = $(firstword $(call _words,$@))
_targ = $(lastword $(call _words,$@))
%_:; $(MAKE) -C $(_dir) $(_targ)
