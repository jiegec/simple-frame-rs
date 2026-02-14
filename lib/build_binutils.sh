#!/bin/sh
set -x -e

git checkout binutils-2_40
rm -f ../gas/doc/.dirstamp
rm -rf * && ../configure --prefix=$HOME/prefix/binutils-2_40 --disable-gdb && make -j16 && make install -j16
git checkout binutils-2_41-release
rm -rf * && ../configure --prefix=$HOME/prefix/binutils-2_41 --disable-gdb && make -j16 && make install -j16
git checkout binutils-2_42
rm -rf * && ../configure --prefix=$HOME/prefix/binutils-2_42 --disable-gdb && make -j16 && make install -j16
git checkout binutils-2_43
rm -rf * && ../configure --prefix=$HOME/prefix/binutils-2_43 --disable-gdb && make -j16 && make install -j16
git checkout binutils-2_44
rm -rf * && ../configure --prefix=$HOME/prefix/binutils-2_44 --disable-gdb && make -j16 && make install -j16
git checkout binutils-2_45
rm -rf * && ../configure --prefix=$HOME/prefix/binutils-2_45 --disable-gdb && make -j16 && make install -j16
git checkout binutils-2_46
rm -rf * && ../configure --prefix=$HOME/prefix/binutils-2_46 --disable-gdb && make -j16 && make install -j16
