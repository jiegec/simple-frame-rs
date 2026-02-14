#!/bin/sh
set -x -e
SUFFIX=$(uname -m)-$(LANG=C as --version | grep -oP '\d+\.\d+' | head -1)
echo $SUFFIX
echo "void foo() {}\nvoid bar() {foo();}\nint main() { return 0; }" > test.c

gcc -Wa,--gsframe test.c -o test
objdump --sframe test
cargo run --example dump_sframe test
cargo run --example create_testcase test
mv testcases/test.json testcases/test-${SUFFIX}.json

gcc -Wa,--gsframe test.c -o test-fp -fomit-frame-pointer
objdump --sframe test-fp
cargo run --example dump_sframe test-fp
cargo run --example create_testcase test-fp
mv testcases/test-fp.json testcases/test-fp-${SUFFIX}.json

rm -rf test.c test test-fp
