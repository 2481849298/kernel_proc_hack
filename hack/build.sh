#!/bin/bash

# 定义颜色变量
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
WHITE="\033[1;37m"
CYAN="\033[1;36m"
NC="\033[0m"


# 内核工作目录
KERNEL_DIR=$(pwd)
# 内核 defconfig 文件
# 编译临时目录，避免污染根目录

#环境配置


export CLANG_PATH=/root/clang-r383902
export GCC64_PATH=/gcc/aarch64
export GCC32_PATH=/root/gcc/arm
# arch平台
ARCH=arm64
SUBARCH=arm64

# 编译时线程指定，默认单线程，可以通过参数指定，比如8线程编译
TH_COUNT=8

# 编译参数
DEF_ARGS="ARCH=${ARCH} \
CROSS_COMPILE=${GCC64_PATH}/bin/aarch64-linux-android- \
CLANG_TRIPLE=${GCC64_PATH}/bin/aarch64-linux-gnu- \
CROSS_COMPILE_ARM32=${GCC32_PATH}/bin/arm-linux-androideabi- \
CC=${CLANG_PATH}/bin/clang \
AR=${CLANG_PATH}/bin/llvm-ar \
NM=${CLANG_PATH}/bin/llvm-nm \
LD=${CLANG_PATH}/bin/ld.lld \
HOSTCC=${CLANG_PATH}/bin/clang \
HOSTCXX=${CLANG_PATH}/bin/clang++ \
OBJCOPY=${CLANG_PATH}/bin/llvm-objcopy \
OBJDUMP=${CLANG_PATH}/bin/llvm-objdump \
READELF=${CLANG_PATH}/bin/llvm-readelf \
OBJSIZE=${CLANG_PATH}/bin/llvm-size \
STRIP=${CLANG_PATH}/bin/llvm-strip \
LLVM_IAS=1 \
LLVM=1"

BUILD_ARGS="-j${TH_COUNT} ${DEF_ARGS}"

# 编译函数
compile_kernel() {

    echo -e "${CYAN}=============== Make module  ===============${NC}"
    start_time=$(date +%s)
     make ${BUILD_ARGS}
    
    # 检查 make 命令是否执行成功
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}>>> build kernel error, exiting!${NC}"
        exit 1
    fi
    
    end_time=$(date +%s)
    total_time=$((end_time - start_time))
    echo -e "${GREEN}>>> build Kernel successful${NC}"
    echo -e "${GREEN}>>> build time: $(($total_time / 60)) minutes and $(($total_time % 60)) seconds${NC}"
}

# 主函数
main() {
    compile_kernel
}

# 调用主函数
main

exit 0
