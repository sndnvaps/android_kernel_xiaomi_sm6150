#!/bin/bash

args="-j15 ARCH=arm64 SUBARCH=arm64 O=$(pwd)/build REAL_CC=clang CROSS_COMPILE=aarch64-linux-gnu- \
CROSS_COMPILER_ARM32=arm-linux-gnueabi- CLANG_TRIPLE=aarch64-linux-gnu- "

make ${args} clean

make ${args} vendor/violet-perf_defconfig

make ${args} Image.gz dtbs

