#pragma once

#include <Windows.h>

EXTERN_C NTSTATUS myCustomDontProtect(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS payexec();
