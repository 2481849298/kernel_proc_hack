# Kernel_proc_hack
> Android/Linux Kernel proc read and write  memory.

# 驱动特性
安卓内核通过进程页目录基址计算虚拟地址的物理页读取物理内存
可过缺页检测
已擦除以下所有可以被特征的文件记录：

/sys/moudle/驱动设备文件夹
/proc/misc
/proc/kallsyms
且 lsmmod 命令也无法打印出来

使用相应型号的内核源码编译驱动文件

使用`insmod xxx`命令即可加载驱动

使用`rmmod xxx`命令即可卸载驱动

使用`dmesg`查看驱动日志

Google官方编译内核教程(只提供GKI内核编译)：`https://source.android.com/docs/setup/build/building-kernels?hl=zh-cn`


请勿拿本项目用作非法用途或商用，本项目开源仅供学习交流，并且源码写的比较烂，还希望各位大佬提交fork优化本驱动模块
