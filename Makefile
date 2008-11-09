
VERSION          = 0.1

NAVISERVER       = /usr/local/ns
NSD              = $(NAVISERVER)/bin/nsd

PHP_CONFIG       = php-config
PHP_LIBS         = $(shell $(PHP_CONFIG) --libs)
PHP_LIBDIR       = $(shell $(PHP_CONFIG) --prefix)/lib
PHP_INCDIRS      = $(shell $(PHP_CONFIG) --includes)

CFLAGS           += $(PHP_INCDIRS)


MODNAME          = nsphp

MOD              = $(MODNAME).so
MODOBJS          = $(MODNAME).o
MODLIBS          = -lphp5 -L$(PHP_LIBDIR) $(PHP_LIBS) 

include $(NAVISERVER)/include/Makefile.module


ifneq (,$(CCRFLAG))
MODLIBS		+= $(CCRFLAG):$(PHP_LIBDIR)
endif


NS_TEST_CFG		= -c -d -t tests/config.tcl
NS_TEST_ALL		= all.tcl $(TCLTESTARGS)
LD_LIBRARY_PATH	= LD_LIBRARY_PATH="./::$$LD_LIBRARY_PATH"

test: all
	export $(LD_LIBRARY_PATH); $(NSD) $(NS_TEST_CFG) $(NS_TEST_ALL)

runtest: all
	export $(LD_LIBRARY_PATH); $(NSD) $(NS_TEST_CFG)

gdbtest: all
	@echo set args $(NS_TEST_CFG) $(NS_TEST_ALL) > gdb.run
	export $(LD_LIBRARY_PATH); gdb -x gdb.run $(NSD)
	rm gdb.run

gdbruntest: all
	@echo set args $(NS_TEST_CFG) > gdb.run
	export $(LD_LIBRARY_PATH); gdb -x gdb.run $(NSD)
	rm gdb.run

memcheck: all
	export $(LD_LIBRARY_PATH); valgrind --tool=memcheck $(NSD) $(NS_TEST_CFG) $(NS_TEST_ALL)



SRCS = nsphp.c
EXTRA = README LICENSE Makefile tests

dist: all
	rm -rf $(MODNAME)-$(VERSION)
	mkdir $(MODNAME)-$(VERSION)
	$(CP) $(SRCS) $(EXTRA) $(MODNAME)-$(VERSION)
	tar czf $(MODNAME)-$(VERSION).tgz $(MODNAME)-$(VERSION)

PHP_HOME = $(NAVISERVER)/php
PHP_VER = php-5.2.6

build:
	if [ ! -e /tmp/$(PHP_VER).tar.gz ]; then \
          wget -c -O /tmp/$(PHP_VER).tar.gz http://www.php.net/distributions/$(PHP_VER).tar.gz; \
        fi
	if [ ! -e $(PHP_VER) ]; then \
          tar -xzf /tmp/$(PHP_VER).tar.gz; \
	fi
	cd $(PHP_VER) && \
	./configure --prefix=$(PHP_HOME) \
                    --mandir=$(PHP_HOME)/man \
                    --enable-debug \
                    --enable-embed=shared \
                    --with-config-file-path=$(PHP_HOME)/etc \
                    --disable-posix \
                    --enable-pdo \
                    --enable-maintainer-zts && \
        make install && \
        cd .. && \
        make install PHP_CONFIG=$(PHP_HOME)/bin/php-config
