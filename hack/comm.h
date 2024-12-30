#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>

struct dan_uct {
	int read_write;//读或者写
	int dan;
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
};

struct process {
    pid_t process_pid;
	char process_comm[15];
};