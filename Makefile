all: force-bind target-mkdir target-bind
.PHONY: all

ifneq ($(debug),)
CFLAGS += -g -O0
endif

force-bind: main.c scm_functions.c *.h
	cc $(CFLAGS) -o $@ $(filter %.c,$+)

target-mkdir: target_mkdir.c *.h
	cc $(CFLAGS) -o $@ $(filter %.c,$+)

target-bind: target_bind.c *.h
	cc $(CFLAGS) -o $@ $(filter %.c,$+)
