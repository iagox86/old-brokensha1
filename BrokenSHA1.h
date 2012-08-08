#ifndef BROKENSHA1_H
#define BROKENSHA1_H

#include <windows.h>

class BrokenSHA1
{
public:
	// This will hash the passed data and place it in the return buffer
	static void hashData(const char *Data, int Length, DWORD returnBuffer[5]);

private:
	// This hashes the next 0x40 bytes
	static void hashNextPart(char Data[0x40], DWORD returnBuffer[5]);
	// This fills the buffer with the initial random-ish data
	static void getInitialData(DWORD hashBuffer[5]);
};

#endif