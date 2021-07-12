#include <stdbool.h>
#include <string.h>

/*
Credit for this function goes to jww at https://stackoverflow.com/questions/25284119/how-can-i-check-if-openssl-is-support-use-the-intel-aes-ni
*/

struct CPUIDinfo {
	unsigned int EAX;
	unsigned int EBX;
	unsigned int ECX;
	unsigned int EDX;
};

static void cpuid_info(struct CPUIDinfo *info, unsigned int func, unsigned int subfunc) {
	__asm__ __volatile__(
	        "cpuid"
	        : "=a"(info->EAX), "=b"(info->EBX), "=c"(info->ECX), "=d"(info->EDX)
	        : "a"(func), "c"(subfunc)
	);
}

bool aesni_has_intel() {
	struct CPUIDinfo info;
	cpuid_info(&info, 0, 0);

	if(memcmp((char *)(&info.EBX), "Genu", 4) == 0
	                && memcmp((char *)(&info.EDX), "ineI", 4) == 0
	                && memcmp((char *)(&info.ECX), "ntel", 4) == 0) {

		return true;
	}

	return false;
}

bool aesni_is_available() {
	if(!aesni_has_intel()) {
		return false;
	}

	struct CPUIDinfo info;

	cpuid_info(&info, 1, 0);

	static const unsigned int AESNI_FLAG = (1 << 25);

	if((info.ECX & AESNI_FLAG) == AESNI_FLAG) {
		return true;
	}

	return false;
}

