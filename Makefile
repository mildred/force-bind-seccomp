all: force-bind target-mkdir
.PHONY: all

force-bind: main.c scm_functions.c
	cc -o $@ $+

target-mkdir: target_mkdir.c
	cc -o $@ $+
