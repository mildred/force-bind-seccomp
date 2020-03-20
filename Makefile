all: force-bind target-mkdir target-bind
.PHONY: all

force-bind: main.c scm_functions.c
	cc -o $@ $+

target-mkdir: target_mkdir.c
	cc -o $@ $+

target-bind: target_bind.c
	cc -o $@ $+
