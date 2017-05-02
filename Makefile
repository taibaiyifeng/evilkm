obj-m += evil.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -masm=intel test_asm_32.c -o test_asm_32
	gcc -masm=intel test_asm_64.c -o test_asm_64 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm test_asm_32
	rm test_asm_64
