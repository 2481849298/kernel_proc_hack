#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define PROC_PATH "/proc/da"

class My_proc{	
	private:   
typedef struct {
	pid_t pid;
	uintptr_t addr;
	void* buffer;
	size_t size;
}comm;

	typedef struct _COPY_MEMORY {
		pid_t pid;
		uintptr_t addr;
		void* buffer;
		size_t size;
	} COPY_MEMORY, *PCOPY_MEMORY;

	typedef struct _MODULE_BASE {
		pid_t pid;
		char* name;
		uintptr_t base;
	} MODULE_BASE, *PMODULE_BASE;
  struct process {
    pid_t process_pid;
    char *process_comm;
  };
  
	enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_HIDE_PROCESS = 0x804,
    OP_PID_HIDE_PROCESS = 0x805,
    OP_GET_PROCESS_PID = 0x806
	};
	

public:
    int pid;
    int fd;
    My_proc(){
        fd = open(PROC_PATH, O_RDWR);
        if(fd == -1){
            printf("链接节点失败 \n");
        }
		if (fd>0){
		    printf("链接节点成功 \n" );
		    printf("节点为%s\n",PROC_PATH);
		}
    }
    
    void offdriver(){
    	close(fd);
    }
    
    void mem_read(long address,void *buffer,size_t size){
    	comm co;
    	co.pid = this->pid;
    	co.addr = address;
    	co.buffer = buffer;
    	co.size = size;
        write(fd, &co, sizeof(co));

        read(fd, &co, sizeof(co));
        //不可能会错误的知道吧
    }


	void initialize(pid_t pid) {
		this->pid = pid;
	}

	bool init_key(char* key) {
		char buf[0x100];
		strcpy(buf,key);
		if (ioctl(fd, OP_INIT_KEY, buf) != 0) {
			return false;
		}
		return true;
	}

	bool read(uintptr_t addr, void *buffer, size_t size) {
		COPY_MEMORY cm;

		cm.pid = this->pid;
		cm.addr = addr;
		cm.buffer = buffer;
		cm.size = size;

		if (ioctl(fd, OP_READ_MEM, &cm) != 0) {
			return false;
		}
		return true;
	}

	bool write(uintptr_t addr, void *buffer, size_t size) {
		COPY_MEMORY cm;

		cm.pid = this->pid;
		cm.addr = addr;
		cm.buffer = buffer;
		cm.size = size;

		if (ioctl(fd, OP_WRITE_MEM, &cm) != 0) {
			return false;
		}
		return true;
	}

	template <typename T>
	T read(uintptr_t addr) {
		T res;
		if (this->read(addr, &res, sizeof(T)))
			return res;
		return {};
	}

	template <typename T>
	bool write(uintptr_t addr,T value) {
		return this->write(addr, &value, sizeof(T));
	}

	uintptr_t get_module_base(char* name) {
		MODULE_BASE mb;
		char buf[0x100];
		strcpy(buf,name);
		mb.pid = this->pid;
		mb.name = buf;

		if (ioctl(fd, OP_MODULE_BASE, &mb) != 0) {
			return 0;
		}
		return mb.base;
	}
	
  void hide_process() { ioctl(fd, OP_HIDE_PROCESS); }

  void hide_pid_process(unsigned int &pid) {
    ioctl(fd, OP_PID_HIDE_PROCESS, pid);
  }
  int kernel_getpid(char *PackageName) {
    struct process pc;
    strcpy(pc.process_comm, PackageName);
    if (ioctl(fd, OP_GET_PROCESS_PID, &pc) != 0) {
      return 0;
    }
    int pid = pc.process_pid;
    if (pid > 0) {
      this->pid = pid;
    } else {
      return 0;
    }
    return pid;
  }
};

static My_proc *driver = new My_proc();

/*--------------------------------------------------------------------------------------------------------*/

typedef char PACKAGENAME;	// 包名
pid_t pid;	// 进程ID

float Kernel_v()
{
	const char* command = "uname -r | sed 's/\\.[^.]*$//g'";
	FILE* file = popen(command, "r");
	if (file == NULL) {
    	return NULL;
	}
	static char result[512];
	if (fgets(result, sizeof(result), file) == NULL) {
		return NULL;
	}
	pclose(file);
    result[strlen(result)-1] = '\0';
	return atof(result);
}

char *GetVersion(char* PackageName)
{
	char command[256];
	sprintf(command, "dumpsys package %s|grep versionName|sed 's/=/\\n/g'|tail -n 1", PackageName);
	FILE* file = popen(command, "r");
	if (file == NULL) {
		return NULL;
	}
	static char result[512];
	if (fgets(result, sizeof(result), file) == NULL) {
		return NULL;
	}
	pclose(file);
	result[strlen(result)-1] = '\0';
	return result;
}

uint64_t GetTime()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC,&ts);
	return (ts.tv_sec*1000 + ts.tv_nsec/(1000*1000));
}

char *getDirectory()
{
	static char buf[128];
	int rslt = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (rslt < 0 || (rslt >= sizeof(buf) - 1))
	{
		return NULL;
	}
	buf[rslt] = '\0';
	for (int i = rslt; i >= 0; i--)
	{
		if (buf[i] == '/')
		{
			buf[i] = '\0';
			break;
		}
	}
	return buf;
}

int getPID(char* PackageName)
{
	FILE* fp;
    char cmd[0x100] = "pidof ";
    strcat(cmd, PackageName);
    fp = popen(cmd,"r");
    fscanf(fp,"%d", &pid);
    pclose(fp);
	if (pid > 0)
	{
		driver->initialize(pid);
	}
    return pid;
}

bool PidExamIne()
{
	char path[128];
	sprintf(path, "/proc/%d",pid);
	if (access(path,F_OK) != 0)
	{
		printf("\033[31;1m");
		puts("获取进程PID失败!");
		exit(1);
	}
	return true;
}

long GetModuleBaseAddr(char* module_name)
{
    long addr = 0;
    char filename[32];
    char line[1024];
    if (pid < 0)
    {
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    }
    else
    {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }
    FILE *fp = fopen(filename, "r");
    if (fp != NULL)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, module_name))
            {
				sscanf(line,"%lx-%*lx",&addr);
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

long getModuleBase(char* module_name)
{
	uintptr_t base=0;
	if (Kernel_v() >= 6.0)
		base = GetModuleBaseAddr(module_name);
	else
		base = driver->get_module_base(module_name);
	return base;
}

long ReadValue(long addr)
{
	long he=0;
	if (addr < 0xFFFFFFFF){
		driver->read(addr, &he, 4);
	}else{
		driver->read(addr, &he, 8);
		he=he&0xFFFFFFFFFFFF;
	}
	return he;
}

long ReadDword(long addr)
{
	long he=0;
	driver->read(addr, &he, 4);
	return he;
}

float ReadFloat(long addr)
{
	float he=0;
	driver->read(addr, &he, 4);
	return he;
}

int *ReadArray(long addr)
{
	int *he = (int *) malloc(12);
	driver->read(addr, he, 12);
	return he;
}

int WriteDword(long int addr, int value)
{
	driver->write(addr, &value, 4);
	return 0;
}

int WriteFloat(long int addr, float value)
{
	driver->write(addr, &value, 4);
	return 0;
}