# simple-frame-rs

Rust crate to parse [SFrame](https://sourceware.org/binutils/wiki/sframe) stack trace format.

Example:

```shell
$ echo "int main() { return 0; }" > test.c
$ gcc -Wa,--gsframe test.c -o test
$ cargo run --example dump_sframe test
# output is similar to: objdump --sframe test
```
