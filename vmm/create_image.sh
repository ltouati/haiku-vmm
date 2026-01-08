#!/bin/bash
echo "cargo::error `pwd`"
find . | cpio -o -H newc | gzip > ../debug_initrd.img