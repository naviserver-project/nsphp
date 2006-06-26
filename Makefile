ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

php_ver 	= php-5.1.4
php_dir 	= /usr/local/php

clean:
	-rm -rf *.so *~ *.o *.lo .libs php-5*

include  $(NAVISERVER)/include/Makefile.module

build:
	rm -rf $(php_ver)
	wget -c -O /tmp/$(php_ver).tar.gz http://www.php.net/distributions/$(php_ver).tar.gz
	tar -xzf /tmp/$(php_ver).tar.gz
	ln -s `pwd` $(php_ver)/sapi/naviserver
	(cd $(php_ver) && \
	./buildconf --force && \
	./configure --prefix=$(php_dir) --with-config-file-path=$(php_dir)/etc \
	--with-naviserver --enable-debug --enable-sockets --enable-soap --enable-calendar \
	--with-openssl --with-zlib --with-curl --enable-dba --with-flatfile --with-gd \
	--with-imap --with-ldap --with-ldap-sasl --with-mcrypt=/usr --with-mhash=/usr \
	--with-mysql --with-pdo-mysql --with-pdo-pgsql --with-pgsql --with-pdo-sqlite \
	--with-xmlrpc --with-pear --enable-fastcgi --enable-bcmath \
	--enable-soap --with-pcre-regex --with-inifile --with-libxml-dir=/usr \
	--with-png-dir=/usr --with-ttf --with-imap-ssl --with-gettext)
	make -C $(php_ver) install
	cp -f $(php_ver)/libs/libphp5.so $(NAVISERVER)/bin


