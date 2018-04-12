#!/bin/zsh

set -x

while read -A line; do
	syscall=${line[1]}
	func=${line[2]}
	file=${line[3]}

#	git checkout -f $syscall
#	patch -f -p2 < patches/$syscall.patch
	rm ${file/%.c/.o}
	make CC=gcc HOSTCC=gcc EXTRA_CFLAGS="-fdump-tree-optimized -fplugin=kayrebt_callgraphs -fplugin-arg-kayrebt_callgraphs-dbfile=db.sqlite"  ${file/%.c/.o} 
#	patch -f -p2 -R < patches/$syscall.patch
#	git checkout -f master
done
