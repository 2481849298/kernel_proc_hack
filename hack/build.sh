#!/bin/bash

# ������ɫ����
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
WHITE="\033[1;37m"
CYAN="\033[1;36m"
NC="\033[0m"


# �ں˹���Ŀ¼
KERNEL_DIR=$(pwd)
# �ں� defconfig �ļ�
# ������ʱĿ¼��������Ⱦ��Ŀ¼

#��������


export CLANG_PATH=/root/clang-r383902
export GCC64_PATH=/gcc/aarch64
export GCC32_PATH=/root/gcc/arm
# archƽ̨
ARCH=arm64
SUBARCH=arm64

# ����ʱ�߳�ָ����Ĭ�ϵ��̣߳�����ͨ������ָ��������8�̱߳���
TH_COUNT=8

# �������
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

# ���뺯��
compile_kernel() {

    echo -e "${CYAN}=============== Make module  ===============${NC}"
    start_time=$(date +%s)
     make ${BUILD_ARGS}
    
    # ��� make �����Ƿ�ִ�гɹ�
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}>>> build kernel error, exiting!${NC}"
        exit 1
    fi
    
    end_time=$(date +%s)
    total_time=$((end_time - start_time))
    echo -e "${GREEN}>>> build Kernel successful${NC}"
    echo -e "${GREEN}>>> build time: $(($total_time / 60)) minutes and $(($total_time % 60)) seconds${NC}"
}

# ������
main() {
    compile_kernel
}

# ����������
main

exit 0
