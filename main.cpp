#include "BrokenSHA1.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char *argv[])
{
	DWORD hash[5];
	char testData[] = "This is my test data! :)";
	BrokenSHA1::hashData(testData, sizeof(testData), hash);
	system("pause");
}