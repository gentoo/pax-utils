SUBDIRS = $(patsubst %/Makefile,%,$(wildcard */Makefile))

.PHONY: all test check clean
all test check clean:
	$(MAKE) $(patsubst %,subdir_%_$@,$(SUBDIRS))

# subdir_source_all
_SUBTAR = $(patsubst subdir_%,%,$@)
_SUBDIR = $(shell expr $(_SUBTAR) : '\(.*\)_[^_]*$$')
_TARGET = $(shell expr $(_SUBTAR) : '.*_\([^_]*\)$$')
subdir_%:
	$(MAKE) -C $(_SUBDIR) $(_TARGET)
