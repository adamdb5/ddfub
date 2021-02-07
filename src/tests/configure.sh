#!/bin/sh
host=`hostname`

if [ "$host" = "Sitara" ] 
then
	mv Makefile.linux Makefile
fi
if [ "$host" = "orangepione" ]
then
        mv Makefile.linux Makefile
fi

if [ "$host" = "ubuntu" ]
then
        mv Makefile.linux Makefile
fi

if [ "$host" = "generic" ]
then
        mv Makefile.freebsd Makefile
fi

if [ "$host" = "armv7" ]
then
        mv Makefile.netbsd Makefile
fi

