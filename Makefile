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
MODOBJS     = nsicmp.o

include  $(NAVISERVER)/include/Makefile.module
