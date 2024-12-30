#include "kernel.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char **argv)
{

	//driver->init_key("!@##$asdcgfxxxop");
	pid = getPID("com.tencent.tmgp.pubgmhd");
	printf("pid = %d\n", pid);
	uint64_t base = driver->getModuleBase("libUE4.so");
	printf("base = %lX\n", base);

	uint64_t base1 = ReadValue(base + 0x0);
	printf("指针 = %p\n", base1);

	int base2 = ReadDword(base + 0x0);
	printf("D类型 = %d\n", base2);

	float base3 = ReadFloat(base + 0x0);
	printf("F类型 = %f\n", base3);
	printf("point 指针 %p\n",driver->read<long>(base));
	printf("float 浮点 %f\n",driver->read<float>(base));
	printf("dword 整形 %d\n",driver->read<int>(base));
	printf("qword 长整形 %ld\n",driver->read<long long>(base));
	printf("word 短整形 %d\n",driver->read<int16_t>(base));
	printf("double 双浮点 %g\n",driver->read<double>(base));
	printf("byte 单字节整形 %d\n",driver->read<int8_t>(base));
	printf("xor 异或 %d\n",driver->read<int>(base)^base);
    std::cout << "666这个入是桂" << std::endl;
	//WriteDword(base, 16345);
	//WriteFloat(base, 17932);
}
