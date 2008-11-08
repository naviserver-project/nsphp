ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

php_ver 	= php-5.2.6
php_dir 	= /usr/local/ns/php


all: configure
	make -C $(php_ver)
	cp $(php_ver)/libs/libphp5.so .

install: all
	make -C $(php_ver) install
	cp $(php_ver)/libs/libphp5.so $(NAVISERVER)/bin

configure:
	if [ ! -e /tmp/$(php_ver).tar.gz ]; then \
	  wget -c -O /tmp/$(php_ver).tar.gz http://www.php.net/distributions/$(php_ver).tar.gz; \
	fi
	if [ ! -e $(php_ver) ]; then \
          tar -xzf /tmp/$(php_ver).tar.gz && \
	  ln -s `pwd` $(php_ver)/sapi/naviserver && \
	  (cd $(php_ver) && \
	   rm -rf configure && \
	   ./buildconf --force && \
  	   ./configure \
	   --prefix=$(php_dir) \
	   --with-config-file-path=$(php_dir)/etc \
	   --mandir=$(php_dir)/man \
	   --with-naviserver \
	   --enable-debug \
	   --disable-posix); \
	fi

clean:
	-rm -rf *.so *~ *.o *.lo .libs php-5*

NSD		= $(NAVISERVER)/bin/nsd
NS_TEST_CFG     = -c -d -t tests/config.tcl
NS_TEST_ALL     = all.tcl $(TCLTESTARGS)
LD_LIBRARY_PATH = LD_LIBRARY_PATH="./:$(NAVISERVER)/lib:$$LD_LIBRARY_PATH"

test: all
	export $(LD_LIBRARY_PATH); $(NSD) $(NS_TEST_CFG) $(NS_TEST_ALL)

runtest: all
	export $(LD_LIBRARY_PATH); $(NSD) $(NS_TEST_CFG)

