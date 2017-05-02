# evilkm
A harmless kernel module that shows how a syscall can be hijacked. Supports newer kernels (4.x) and the x86-64 architecture.
I'm uploading this module because I've been using it for testing a hobbyist kernel patch protection system I started to code as a learning project.

** usage: **
1. git clone
2. cd evilkm
3. make
4. launch test_asm_32 or test_asm_64 depending on your architecture

** dmesg output (x86-64): **

[ ... ] [evil] IDT found @ 0xffffffffff57c000
[ ... ] [evil] entry_INT80_compat found @ 0xffffffff81633620
[ ... ] [evil] do_int80_syscall_32 found @ 0xffffffff81003bd0
[ ... ] [evil] syscall_table found @ 0xffffffff81800e40
[ ... ] [evil] sys_kill is @ 0xffffffff81277580
[ ... ] [evil] stealing sys_kill syscall...

* after launching test_asm_64... *

[ ... ] [evil] :)

