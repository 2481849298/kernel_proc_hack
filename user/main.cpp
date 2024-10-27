#include "kernel.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char **argv)
{
	// driver->init_key("paste your driver verify key here");
	PACKAGENAME *bm = "com.tencent.tmgp.pubgmhd";
	pid = getPID("com.tencent.tmgp.pubgmhd");
	printf("pid = %d\n", pid);
	uint64_t add = getModuleBase("libUE4.so");
	printf("base = %lX\n", add);

	uint64_t add1 = ReadValue(add + 0x0);
	printf("指针 = %p\n", add1);

	int add2 = ReadDword(add + 0x0);
	printf("D类型 = %d\n", add2);

	float add3 = ReadFloat(add + 0x0);
	printf("F类型 = %f\n", add3);
std::cout << "666这个入是桂" << std::endl;
	// WriteDword(add, 139445);
	// WriteFloat(add, 3491613643194);
}
