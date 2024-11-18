//by @dan 2481819298
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <limits.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>

class c_driver {	
	private:  
	pid_t pid;
	int fd;
    char path[256];

	
	struct dan_uct {
    	int read_write;//读或者写
		pid_t pid;
		uintptr_t addr;
		void *buffer;
		size_t size;
	};
/*	typedef struct _MODULE_BASE {
		pid_t pid;
		char* name;
		uintptr_t base;
	} MODULE_BASE, *PMODULE_BASE;*/
  struct process {
    pid_t process_pid;
    char *process_comm;
  };
/*enum OPERATIONS {
    OP_INIT_KEY = 0x990,
    OP_READ_MEM = 0x999,
    OP_WRITE_MEM = 0x998,
//    OP_MODULE_BASE = 0x997,
    OP_HIDE_PROCESS = 0x996,
    OP_PID_HIDE_PROCESS = 0x995,
    OP_GET_PROCESS_PID = 0x994
};*/

	char *driver_path() {
	DIR *dir;
	struct dirent *entry;
	dir = opendir("/proc");
	if (dir == NULL)
	{
		perror("无法打开/proc");
		return NULL;
	}

  
    while ((entry = readdir(dir)) != NULL) {
			// 跳过当前目录和上级目录
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
				continue;
			}
			//过滤某些特殊文件
      if (strlen(entry->d_name) != 6 || strcmp(entry->d_name, "NVTSPI") == 0 || strcmp(entry->d_name, "ccci_log") == 0 || strcmp(entry->d_name, "aputag") == 0 || strcmp(entry->d_name, "asound") == 0 || strcmp(entry->d_name, "clkdbg") == 0 || strcmp(entry->d_name, "crypto") == 0 || strcmp(entry->d_name, "modules") == 0 || strcmp(entry->d_name, "mounts") == 0 || strcmp(entry->d_name, "pidmap") == 0 || strcmp(entry->d_name, "phoenix") == 0) {
        continue;
      }

        struct stat statbuf;        
       snprintf(path, sizeof(path), "/proc/%s", entry->d_name); // 构建文件的完整路径
        //检测stat结构
        if (stat(path, &statbuf) < 0) {
            continue;
        }
		if ((S_ISREG(statbuf.st_mode))  // 确保是普通文件，不是目录
                    //大小还有gid和uid是否为0(root)并且文件名称长度在6位
					&& statbuf.st_size == 0
					&& statbuf.st_gid == 0
					&& statbuf.st_uid == 0
					&& ((statbuf.st_mode & (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) == (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH))) {

	
               return path;
}
}

	closedir(dir);
    return NULL;
    }


    
    
/*    void mem_read(long address,void *buffer,size_t size){
    	comm co;
    	co.pid = this->pid;
    	co.addr = address;
    	co.buffer = buffer;
    	co.size = size;
        write(fd, &co, sizeof(co));

        read(fd, &co, sizeof(co));
        //不可能会错误的知道吧
    }*/
	int open_driver() {

		char *dev_path1 = driver_path();
		if (dev_path1 != NULL) {
			fd = open(dev_path1, O_RDWR);
			if (fd>0){
				printf("[-] 驱动文件：%s\n", dev_path1);
				return 1;
			}
		}

        return 0;
        }
	
	public:
	c_driver() {
		open_driver();
		if (fd <= 0) {
			printf("[-] 连接驱动失败，你赶紧重开吧\n");
			exit(0);
		}
	}

	~c_driver() {
		//wont be called
		if (fd > 0) {
			close(fd);
			}
	}



	void initialize(pid_t pid) {
		this->pid = pid;
	}
	
	bool init_key(char* key) {
		char buf[0x100];
		strcpy(buf,key);
		if (ioctl(fd, 0x900, buf) != 0) {
			return false;
		}
		return true;
	}

	bool read(uintptr_t addr, void *buffer, size_t size) {
		struct dan_uct dan;
		dan.pid = this->pid;
		dan.addr = addr;
		dan.buffer = buffer;
		dan.size = size;
        dan.read_write = 0x999;
		if (ioctl(fd, 0x999, &dan) != 0) {
			return false;
		}
		return true;
	}

	bool write(uintptr_t addr, void *buffer, size_t size) {
		struct dan_uct dan;

		dan.pid = this->pid;
		dan.addr = addr;
		dan.buffer = buffer;
		dan.size = size;
        dan.read_write = 0x998;
		if (ioctl(fd, 0x998, &dan) != 0) {
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

/*	uintptr_t get_module_base(char* name) {
		MODULE_BASE wudi;
		char buf[0x100];
		strcpy(buf,name);
		wudi.pid = this->pid;
		wudi.name = buf;

		if (ioctl(fd, OP_MODULE_BASE, &wudi) != 0) {
			return 0;
		}
		return wudi.base;
	}*/
	
unsigned long GetModuleBaseAddr(const char *module_name)
{
	FILE *fp;
	unsigned long addr = 0;
	char *pch;
	char filename[64];
	char line[1024];
	snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if (fp != NULL)
	{
		while (fgets(line, sizeof(line), fp))
		{
			if (strstr(line, module_name))
			{
				pch = strtok(line, "-");
				addr = strtoul(pch, NULL, 16);
				if (addr == 0x8000)
					addr = 0;
				break;
			}
		}
		fclose(fp);
	}
	return addr;
}
  void hide_process() { ioctl(fd, 0x996); }

  void hide_pid_process(unsigned int &pid) {
    ioctl(fd, 0x995, pid);
  }
  int kernel_getpid(char *PackageName) {
    struct process pc;
    strcpy(pc.process_comm, PackageName);
    if (ioctl(fd, 0x994, &pc) != 0) {
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

static c_driver *driver = new c_driver();

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


long getModuleBase(char* module_name)
{
	uintptr_t base=0;
//	if (Kernel_v() >= 6.0)
		base = driver->GetModuleBaseAddr(module_name);
//	else
//		base = driver->get_module_base(module_name);
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