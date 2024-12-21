#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>

struct dan_uct {
	int read_write;//读或者写
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
};

struct process {
    pid_t process_pid;
	char process_comm[15];
};
enum OPERATIONS {
    OP_INIT_KEY = 0x990,
    OP_READ_MEM = 0x999,
    OP_WRITE_MEM = 0x998,
//    OP_MODULE_BASE = 0x997,
    OP_HIDE_PROCESS = 0x996,
    OP_PID_HIDE_PROCESS = 0x995,
    OP_GET_PROCESS_PID = 0x994,
};