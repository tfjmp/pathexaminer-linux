#!/bin/zsh

set -x

while read -A line; do
	syscall=${line[1]}
	func=${line[2]}
	file=${line[3]}

	patch -f -p2 < patches/$syscall.patch
	rm ${file/%.c/.o}
	make CC=gcc-4.8.5 HOSTCC=gcc-4.8.5 EXTRA_CFLAGS="-fdump-tree-optimized -fplugin=kayrebt_pathexaminer2 -fplugin-arg-kayrebt_pathexaminer2-function=$func"  ${file/%.c/.o} 2> patches/$syscall.result
	patch -f -p2 -R < patches/$syscall.patch
done
