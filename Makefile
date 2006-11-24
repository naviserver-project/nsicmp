ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nsicmp.so

#
# Objects to build.
#
OBJS     = nsicmp.o

include  $(NAVISERVER)/include/Makefile.module
