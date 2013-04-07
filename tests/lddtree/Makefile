all: check

%.check:
	./dotest.$(@:.check=)

test check: sh.check
ifeq ($(USE_PYTHON),yes)
test check: py.check cmp.check
endif

clean:

.PHONY: all check clean test
