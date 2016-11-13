/* compile with gcc -masm=intel test_asm_64.c -o test_asm_64 */

int main(int argc, char **argv)
{
	asm("xor rax, rax");
	asm("mov rax, 62");
	asm("int 0x80");
	return 0;
}
