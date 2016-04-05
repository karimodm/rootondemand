#!/bin/sh
grep "sys_exit" /proc/kallsyms
echo
echo "FIRST LINE ;P :"
hexdump /usr/src/linux/vmlinux | grep "c011" | grep "a940"
echo
grep "sys_fork" /proc/kallsyms
echo
grep "sys_read" /proc/kallsyms
