all: check

%.check:
	./dotest.$(@:.check=)

test check: sh.check
ifneq ($(USE_PYTHON),no)
test check: py.check cmp.check
endif

clean:

.PHONY: all check clean test
