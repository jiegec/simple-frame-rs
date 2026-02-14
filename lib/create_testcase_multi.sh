#!/bin/bash
set -x -e
# SFrame V1: 2.40
PATH=~/prefix/binutils-2_40/bin:$PATH CUSTOM_BINUTILS_PATH=~/prefix/binutils-2_40/bin ./create_testcase.sh
# SFrame V2: 2.41 to 2.45
PATH=~/prefix/binutils-2_45/bin:$PATH CUSTOM_BINUTILS_PATH=~/prefix/binutils-2_41/bin ./create_testcase.sh
PATH=~/prefix/binutils-2_45/bin:$PATH CUSTOM_BINUTILS_PATH=~/prefix/binutils-2_42/bin ./create_testcase.sh
PATH=~/prefix/binutils-2_45/bin:$PATH CUSTOM_BINUTILS_PATH=~/prefix/binutils-2_43/bin ./create_testcase.sh
PATH=~/prefix/binutils-2_45/bin:$PATH CUSTOM_BINUTILS_PATH=~/prefix/binutils-2_44/bin ./create_testcase.sh
PATH=~/prefix/binutils-2_45/bin:$PATH CUSTOM_BINUTILS_PATH=~/prefix/binutils-2_45/bin ./create_testcase.sh
# SFrame V3: 2.46
PATH=~/prefix/binutils-2_46/bin:$PATH CUSTOM_BINUTILS_PATH=~/prefix/binutils-2_46/bin ./create_testcase.sh
