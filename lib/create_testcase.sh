#!/bin/sh
set -x -e
echo "int main() { return 0; }" > test.c
gcc -Wa,--gsframe test.c -o test
cargo run --example dump_sframe test
cargo run --example create_testcase test
rm -rf test.c test