/* compile with gcc -masm=intel test_asm_32.c -o test_asm_32 */

int main(int argc, char **argv)
{
	asm("xor eax, eax");
	asm("mov eax, 37");
	asm("int 0x80");
	return 0;
}
