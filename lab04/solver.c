#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "hello, world!";
    fptr("\ncanary:   0x%016" PRIx64 "\n", *(uint64_t *)(msg+0x18)); 
    fptr("rbp:      0x%016" PRIx64 "\n", *(uint64_t *)(msg+0x20)); 
    fptr("ret addr: 0x%016" PRIx64 "\n", *(uint64_t *)(msg+0x28));
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}
