ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

clean:
	-rm -rf *.so *~ *.o .libs

include  $(NAVISERVER)/include/Makefile.module

