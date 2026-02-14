#!/bin/bash
set -x -e
# you can generate sframe using one binutils from CUSTOM_BINUTILS_PATH
# while generate the groundtruth using another binutils from PATH
SUFFIX=$(uname -m)-$(LANG=C PATH=$CUSTOM_BINUTILS_PATH:$PATH as --version | grep -oP '\d+\.\d+' | head -1)
echo $SUFFIX
echo -e "void foo() {}\nvoid bar() {foo();}\nint main() { return 0; }" > test.c

PATH=$CUSTOM_BINUTILS_PATH:$PATH gcc -Wa,--gsframe test.c -o test
objdump --sframe test
cargo run --example dump_sframe test
cargo run --example create_testcase test
mv testcases/test.json testcases/test-${SUFFIX}.json

PATH=$CUSTOM_BINUTILS_PATH:$PATH gcc -Wa,--gsframe test.c -o test-fp -fomit-frame-pointer
objdump --sframe test-fp
cargo run --example dump_sframe test-fp
cargo run --example create_testcase test-fp
mv testcases/test-fp.json testcases/test-fp-${SUFFIX}.json

rm -rf test.c test test-fp
