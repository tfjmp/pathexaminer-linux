#!/bin/zsh

curdir="$(pwd)"
repo="$1"
base_commit=bbb70443

pushd $repo
while read -A line; do
	syscall=${line[1]}
	branch=${line[2]}
	commit=${line[3]}
	patch_file="$curdir/$syscall.patch"
	git checkout $branch
	git diff -p $base_commit $commit -- . > $patch_file
done
popd
