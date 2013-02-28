#!/bin/sh

aclocal -I config
glibtoolize --automake --copy
autoheader
automake --add-missing --include-deps --copy
autoconf
