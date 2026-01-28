#!/bin/bash
# Build libbpf SDK for Android ARM64
# This script builds libbpf as a static library (.a) with headers for Android
#
# Usage: ./build-libbpf-android.sh [arm64|x86_64]
# Default architecture: arm64
#
# Requirements (Ubuntu):
#   sudo apt-get install -y build-essential curl git autoconf automake libtool pkg-config m4 unzip gettext bison

set -e

#######################
# Configuration
#######################

# Target architecture (arm64 or x86_64)
ARCH="${1:-arm64}"

# Android NDK version and API level
NDK_VERSION="r27b"
NDK_API="30"

# Library versions
LIBBPF_VERSION="v1.5.0"
ELFUTILS_VERSION="0.191"
ZLIB_VERSION="1.3.1"
GNULIB_VERSION="v1.0"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="${SCRIPT_DIR}/libbpf-android-build"
DOWNLOAD_DIR="${BUILD_ROOT}/downloads"
SRC_DIR="${BUILD_ROOT}/src"
BUILD_DIR="${BUILD_ROOT}/build/${ARCH}"
OUTPUT_DIR="${BUILD_ROOT}/sdk/${ARCH}"
NDK_DIR="${BUILD_ROOT}/ndk/android-ndk-${NDK_VERSION}"

# Thread count
THREADS=$(nproc)

#######################
# Architecture Settings
#######################

case "${ARCH}" in
    arm64)
        ANDROID_TRIPLE="aarch64-linux-android"
        ANDROID_ABI="arm64-v8a"
        ANDROID_MAX_PAGE_SIZE="16384"
        ;;
    x86_64)
        ANDROID_TRIPLE="x86_64-linux-android"
        ANDROID_ABI="x86_64"
        ANDROID_MAX_PAGE_SIZE="16384"
        ;;
    *)
        echo "Error: Unsupported architecture '${ARCH}'"
        echo "Supported: arm64, x86_64"
        exit 1
        ;;
esac

ANDROID_TOOLCHAIN="${NDK_DIR}/toolchains/llvm/prebuilt/linux-x86_64"
ANDROID_SYSROOT="${ANDROID_TOOLCHAIN}/sysroot"

# Compiler paths
CC="${ANDROID_TOOLCHAIN}/bin/${ANDROID_TRIPLE}${NDK_API}-clang"
CXX="${ANDROID_TOOLCHAIN}/bin/${ANDROID_TRIPLE}${NDK_API}-clang++"
AR="${ANDROID_TOOLCHAIN}/bin/llvm-ar"
RANLIB="${ANDROID_TOOLCHAIN}/bin/llvm-ranlib"
STRIP="${ANDROID_TOOLCHAIN}/bin/llvm-strip"

#######################
# Helper Functions
#######################

log_info() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1"
}

create_dirs() {
    log_info "Creating build directories..."
    mkdir -p "${DOWNLOAD_DIR}"
    mkdir -p "${SRC_DIR}"
    mkdir -p "${BUILD_DIR}"
    mkdir -p "${OUTPUT_DIR}/lib"
    mkdir -p "${OUTPUT_DIR}/include"
    mkdir -p "${OUTPUT_DIR}/lib/pkgconfig"
    mkdir -p "${OUTPUT_DIR}/share"
}

#######################
# Create config.site for autotools cross-compilation
#######################

create_config_site() {
    local CONFIG_SITE="${OUTPUT_DIR}/share/config.site"
    
    # Following the original project's config.site.template approach
    # EXTRA_CFLAGS, EXTRA_CPPFLAGS, EXTRA_LDFLAGS are appended at configure time
    cat > "${CONFIG_SITE}" << EOF
# Config site for Android cross-compilation
# Following original project's config.site.template

test -z "\$AR" && AR="${AR}"
test -z "\$CC" && CC="${CC}"
test -z "\$CXX" && CXX="${CXX}"
test -z "\$RANLIB" && RANLIB="${RANLIB}"
test -z "\$STRIP" && STRIP="${STRIP}"

test -z "\$PKG_CONFIG_LIBDIR" && PKG_CONFIG_LIBDIR="${OUTPUT_DIR}/lib/pkgconfig"
test -z "\$CPPFLAGS" && CPPFLAGS="-I${OUTPUT_DIR}/include \$EXTRA_CPPFLAGS"
test -z "\$CFLAGS" && CFLAGS="-fPIC \$EXTRA_CFLAGS"
test -z "\$LDFLAGS" && LDFLAGS="-L${OUTPUT_DIR}/lib -L${OUTPUT_DIR}/lib64 -Wl,-z,max-page-size=${ANDROID_MAX_PAGE_SIZE} \$EXTRA_LDFLAGS"

# Cache values for tests that can't run during cross-compilation
ac_cv_func_malloc_0_nonnull=yes
ac_cv_func_realloc_0_nonnull=yes
gl_cv_func_working_strerror=yes
gl_cv_func_strerror_0_works=yes
EOF

    echo "${CONFIG_SITE}"
}

#######################
# Download Functions
#######################

download_ndk() {
    if [ -d "${NDK_DIR}" ]; then
        log_info "NDK already exists, skipping download..."
        return
    fi
    
    log_info "Downloading Android NDK ${NDK_VERSION}..."
    local NDK_URL="https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip"
    local NDK_ZIP="${DOWNLOAD_DIR}/android-ndk-${NDK_VERSION}.zip"
    
    if [ ! -f "${NDK_ZIP}" ]; then
        curl -L "${NDK_URL}" -o "${NDK_ZIP}"
    fi
    
    log_info "Extracting NDK..."
    mkdir -p "${BUILD_ROOT}/ndk"
    unzip -q "${NDK_ZIP}" -d "${BUILD_ROOT}/ndk"
}

download_zlib() {
    if [ -d "${SRC_DIR}/zlib" ]; then
        log_info "zlib source already exists, skipping..."
        return
    fi
    
    log_info "Downloading zlib ${ZLIB_VERSION}..."
    local ZLIB_URL="https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
    local ZLIB_TAR="${DOWNLOAD_DIR}/zlib-${ZLIB_VERSION}.tar.gz"
    
    if [ ! -f "${ZLIB_TAR}" ]; then
        curl -L "${ZLIB_URL}" -o "${ZLIB_TAR}"
    fi
    
    tar xf "${ZLIB_TAR}" -C "${SRC_DIR}"
    mv "${SRC_DIR}/zlib-${ZLIB_VERSION}" "${SRC_DIR}/zlib"
}

download_elfutils() {
    if [ -d "${SRC_DIR}/elfutils" ]; then
        log_info "elfutils source already exists, skipping..."
        return
    fi
    
    log_info "Downloading elfutils ${ELFUTILS_VERSION}..."
    local ELFUTILS_URL="https://sourceware.org/pub/elfutils/${ELFUTILS_VERSION}/elfutils-${ELFUTILS_VERSION}.tar.bz2"
    local ELFUTILS_TAR="${DOWNLOAD_DIR}/elfutils-${ELFUTILS_VERSION}.tar.bz2"
    
    if [ ! -f "${ELFUTILS_TAR}" ]; then
        curl -L "${ELFUTILS_URL}" -o "${ELFUTILS_TAR}"
    fi
    
    tar xf "${ELFUTILS_TAR}" -C "${SRC_DIR}"
    mv "${SRC_DIR}/elfutils-${ELFUTILS_VERSION}" "${SRC_DIR}/elfutils"
}

download_libbpf() {
    if [ -d "${SRC_DIR}/libbpf" ]; then
        log_info "libbpf source already exists, skipping..."
        return
    fi
    
    log_info "Cloning libbpf ${LIBBPF_VERSION}..."
    git clone --depth 1 -b "${LIBBPF_VERSION}" https://github.com/libbpf/libbpf.git "${SRC_DIR}/libbpf"
}

download_gnulib() {
    if [ -d "${SRC_DIR}/gnulib" ]; then
        log_info "gnulib source already exists, skipping..."
        return
    fi
    
    log_info "Cloning gnulib..."
    git clone --depth 1 https://git.savannah.gnu.org/git/gnulib.git "${SRC_DIR}/gnulib"
}

#######################
# Build Functions
#######################

generate_argp_sources() {
    if [ -d "${SRC_DIR}/argp-standalone" ]; then
        log_info "argp sources already exist, skipping..."
        return
    fi
    
    log_info "Generating argp sources from gnulib..."
    
    cd "${SRC_DIR}/gnulib"
    ./gnulib-tool --create-testdir \
        --lgpl \
        --lib="libargp" \
        --dir="${SRC_DIR}/argp-standalone" \
        argp
}

generate_obstack_sources() {
    if [ -d "${SRC_DIR}/obstack-standalone" ]; then
        log_info "obstack sources already exist, skipping..."
        return
    fi
    
    log_info "Generating obstack sources from gnulib..."
    
    cd "${SRC_DIR}/gnulib"
    ./gnulib-tool --create-testdir \
        --lgpl \
        --lib="libobstack" \
        --dir="${SRC_DIR}/obstack-standalone" \
        obstack
}

build_argp() {
    log_info "Building argp for Android ${ARCH}..."
    
    local ARGP_BUILD="${BUILD_DIR}/argp"
    mkdir -p "${ARGP_BUILD}"
    
    local CONFIG_SITE=$(create_config_site)
    
    cd "${ARGP_BUILD}"
    
    CONFIG_SITE="${CONFIG_SITE}" \
    "${SRC_DIR}/argp-standalone/configure" \
        --host="${ANDROID_TRIPLE}" \
        --prefix="${OUTPUT_DIR}"
    
    make -j${THREADS}
    
    # Install library - the .a file is in the build directory
    cp "${ARGP_BUILD}/gllib/libargp.a" "${OUTPUT_DIR}/lib/"
    
    # Install headers - argp.h is in the SOURCE directory's gllib folder
    # We need a wrapper header and the real header
    cp "${SRC_DIR}/argp-standalone/gllib/argp.h" "${OUTPUT_DIR}/include/argp-real.h"
    
    # Create argp.h wrapper (required for gnulib's argp.h to work properly)
    cat > "${OUTPUT_DIR}/include/argp.h" << 'EOF'
// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef ARGP_WRAPPER_H
#define ARGP_WRAPPER_H

#ifndef ARGP_EI
#  define ARGP_EI inline
#endif

// gnulib's argp.h checks for _GL_CONFIG_H_INCLUDED to ensure config.h is included first.
// We bypass this by defining it here since we provide all necessary definitions.
#ifndef _GL_CONFIG_H_INCLUDED
#  define _GL_CONFIG_H_INCLUDED 1
#endif

// since ece81a73b64483a68f5157420836d84beb3a1680 argp.h as distributed with
// gnulib requires _GL_INLINE_HEADER_BEGIN macro to be defined.
#ifndef _GL_INLINE_HEADER_BEGIN
#  define _GL_INLINE_HEADER_BEGIN
#  define _GL_INLINE_HEADER_END
#endif

#ifndef _GL_ATTRIBUTE_FORMAT
#  define _GL_ATTRIBUTE_FORMAT(spec) __attribute__ ((__format__ spec))
#endif

#ifndef _GL_ATTRIBUTE_SPEC_PRINTF_SYSTEM
#  define _GL_ATTRIBUTE_SPEC_PRINTF_SYSTEM __printf__
#endif

#include "argp-real.h"
#endif
EOF
    
    log_info "argp built successfully"
}

build_obstack() {
    log_info "Building obstack for Android ${ARCH}..."
    
    local OBSTACK_BUILD="${BUILD_DIR}/obstack"
    mkdir -p "${OBSTACK_BUILD}"
    
    local CONFIG_SITE=$(create_config_site)
    
    cd "${OBSTACK_BUILD}"
    
    CONFIG_SITE="${CONFIG_SITE}" \
    "${SRC_DIR}/obstack-standalone/configure" \
        --host="${ANDROID_TRIPLE}" \
        --prefix="${OUTPUT_DIR}"
    
    make -j${THREADS}
    
    # Install library from BUILD directory
    cp "${OBSTACK_BUILD}/gllib/libobstack.a" "${OUTPUT_DIR}/lib/"
    
    # Install header - try source directory first (original project approach),
    # then fall back to build directory (some gnulib versions generate it there)
    if [ -f "${SRC_DIR}/obstack-standalone/gllib/obstack.h" ]; then
        cp "${SRC_DIR}/obstack-standalone/gllib/obstack.h" "${OUTPUT_DIR}/include/obstack.h"
    elif [ -f "${OBSTACK_BUILD}/gllib/obstack.h" ]; then
        cp "${OBSTACK_BUILD}/gllib/obstack.h" "${OUTPUT_DIR}/include/obstack.h"
    else
        log_error "obstack.h not found in source or build directory!"
        log_info "Searching for obstack.h..."
        find "${SRC_DIR}/obstack-standalone" -name "obstack.h" 2>/dev/null || true
        find "${OBSTACK_BUILD}" -name "obstack.h" 2>/dev/null || true
        exit 1
    fi
    
    log_info "obstack built successfully"
}

build_zlib() {
    log_info "Building zlib for Android ${ARCH}..."
    
    local ZLIB_BUILD="${BUILD_DIR}/zlib"
    mkdir -p "${ZLIB_BUILD}"
    
    cd "${SRC_DIR}/zlib"
    
    # Clean previous build
    make distclean 2>/dev/null || true
    
    # Configure for Android cross-compilation
    CHOST="${ANDROID_TRIPLE}" \
    CC="${CC}" \
    AR="${AR}" \
    RANLIB="${RANLIB}" \
    CFLAGS="-O2 -fPIC" \
    ./configure \
        --prefix="${OUTPUT_DIR}" \
        --static
    
    make -j${THREADS}
    make install
    
    log_info "zlib built successfully"
}

create_android_fixups() {
    # Create Android compatibility headers (following original project's approach)
    log_info "Creating Android compatibility headers..."
    
    local FIXUP_DIR="${BUILD_DIR}/android_fixups"
    mkdir -p "${FIXUP_DIR}"
    
    # Create libintl.h - following the original project exactly
    # elfutils includes this but we don't need gettext functionality
    cat > "${FIXUP_DIR}/libintl.h" << 'EOF'
// libintl.h is included in a lot of sources in elfutils, but provided
// functionalities are not really necessary. Because of that we follow
// the AOSP example and provide a fake header turning some functions into
// nops with macros

#ifndef LIBINTL_H
#define LIBINTL_H

#define gettext(x)      (x)
#define dgettext(x,y)   (y)

#endif
EOF
}

build_elfutils() {
    log_info "Building elfutils (libelf only) for Android ${ARCH}..."
    
    local ELFUTILS_BUILD="${BUILD_DIR}/elfutils"
    
    # Clean previous build to ensure fresh configure with correct EXTRA_CFLAGS
    rm -rf "${ELFUTILS_BUILD}"
    mkdir -p "${ELFUTILS_BUILD}"
    
    create_android_fixups
    
    local FIXUP_DIR="${BUILD_DIR}/android_fixups"
    
    # Extra CFLAGS for Android compatibility - following original project's approach
    # The original project uses EXTRA_CFLAGS environment variable which gets merged
    # into CFLAGS in config.site during configure
    local ELFUTILS_EXTRA_CFLAGS="-I${FIXUP_DIR}"
    ELFUTILS_EXTRA_CFLAGS+=" -I${OUTPUT_DIR}/include"
    ELFUTILS_EXTRA_CFLAGS+=" -Dprogram_invocation_short_name=\\\"elfutils\\\""
    
    cd "${ELFUTILS_BUILD}"
    
    local CONFIG_SITE=$(create_config_site)

    # Configure elfutils with argp and obstack from our build
    # EXTRA_CFLAGS is merged into CFLAGS via config.site (see create_config_site)
    EXTRA_CFLAGS="${ELFUTILS_EXTRA_CFLAGS}" \
    LIBS="-largp -lobstack" \
    CONFIG_SITE="${CONFIG_SITE}" \
    "${SRC_DIR}/elfutils/configure" \
        --host="${ANDROID_TRIPLE}" \
        --prefix="${OUTPUT_DIR}" \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --enable-install-elfh \
        --disable-nls \
        --without-lzma \
        --without-bzlib \
        --without-zstd
    
    # Build only libelf (that's all libbpf needs)
    # No need to pass CFLAGS here - configure already set them up correctly
    make -C lib -j${THREADS}
    make -C libelf -j${THREADS}
    make -C libelf install
    
    # Build and install libelf.pc
    make -C config
    if [ -f "${ELFUTILS_BUILD}/config/libelf.pc" ]; then
        cp "${ELFUTILS_BUILD}/config/libelf.pc" "${OUTPUT_DIR}/lib/pkgconfig/"
    fi
    
    log_info "elfutils (libelf) built successfully"
}

build_libbpf() {
    log_info "Building libbpf for Android ${ARCH}..."
    
    local LIBBPF_BUILD="${BUILD_DIR}/libbpf"
    mkdir -p "${LIBBPF_BUILD}"
    
    # Extra CFLAGS for Android/libbpf compatibility
    local EXTRA_CFLAGS=""
    EXTRA_CFLAGS+=" -D__user="
    EXTRA_CFLAGS+=" -D__force="
    EXTRA_CFLAGS+=" -D__poll_t=unsigned"
    EXTRA_CFLAGS+=" -Wno-tautological-constant-out-of-range-compare"
    EXTRA_CFLAGS+=" -I${OUTPUT_DIR}/include"
    EXTRA_CFLAGS+=" -fPIC"
    
    local EXTRA_LDFLAGS=""
    EXTRA_LDFLAGS+=" -L${OUTPUT_DIR}/lib"
    EXTRA_LDFLAGS+=" -Wl,-z,max-page-size=${ANDROID_MAX_PAGE_SIZE}"
    
    cd "${SRC_DIR}/libbpf/src"
    
    # Clean previous build
    make clean 2>/dev/null || true
    
    # Build libbpf
    PKG_CONFIG_LIBDIR="${OUTPUT_DIR}/lib/pkgconfig" \
    make install install_uapi_headers \
        -j${THREADS} \
        LIBSUBDIR=lib \
        PREFIX="${OUTPUT_DIR}" \
        OBJDIR="${LIBBPF_BUILD}" \
        AR="${AR}" \
        CC="${CC}" \
        EXTRA_CFLAGS="${EXTRA_CFLAGS}" \
        EXTRA_LDFLAGS="${EXTRA_LDFLAGS}"
    
    log_info "libbpf built successfully"
}

#######################
# Package SDK
#######################

package_sdk() {
    log_info "Packaging SDK..."
    
    local SDK_PACKAGE="${BUILD_ROOT}/libbpf-android-sdk-${ARCH}.tar.gz"
    
    # Create SDK structure info
    cat > "${OUTPUT_DIR}/README.txt" << EOF
libbpf Android SDK
==================

Architecture: ${ARCH} (${ANDROID_ABI})
Android API Level: ${NDK_API}
NDK Version: ${NDK_VERSION}

Versions:
- libbpf: ${LIBBPF_VERSION}
- elfutils: ${ELFUTILS_VERSION}
- zlib: ${ZLIB_VERSION}

Directory Structure:
- include/  : Header files (bpf/, elf.h, libelf.h, gelf.h, etc.)
- lib/      : Static libraries (libbpf.a, libelf.a, libz.a)
- lib/pkgconfig/ : pkg-config files

Usage in Android.bp (AOSP):
--------------------------
cc_library_static {
    name: "libbpf",
    export_include_dirs: ["include"],
    srcs: ["lib/libbpf.a"],
    // ... 
}

Usage with ndk-build:
--------------------
LOCAL_STATIC_LIBRARIES := libbpf libelf libz

Usage with CMake:
----------------
target_include_directories(your_target PRIVATE \${SDK_PATH}/include)
target_link_libraries(your_target \${SDK_PATH}/lib/libbpf.a \${SDK_PATH}/lib/libelf.a \${SDK_PATH}/lib/libz.a)

Build Date: $(date)
EOF

    # Create tarball
    cd "${BUILD_ROOT}/sdk"
    tar czf "${SDK_PACKAGE}" "${ARCH}"
    
    log_info "SDK packaged: ${SDK_PACKAGE}"
}

print_summary() {
    echo ""
    echo "========================================"
    echo "  libbpf Android SDK Build Complete!"
    echo "========================================"
    echo ""
    echo "Architecture: ${ARCH}"
    echo "Output directory: ${OUTPUT_DIR}"
    echo ""
    echo "Contents:"
    echo "  Headers:  ${OUTPUT_DIR}/include/"
    ls -la "${OUTPUT_DIR}/include/" 2>/dev/null | head -10
    echo ""
    echo "  Libraries: ${OUTPUT_DIR}/lib/"
    ls -la "${OUTPUT_DIR}/lib/"*.a 2>/dev/null
    echo ""
    echo "SDK Package: ${BUILD_ROOT}/libbpf-android-sdk-${ARCH}.tar.gz"
    echo ""
}

#######################
# Main
#######################

main() {
    log_info "Building libbpf SDK for Android ${ARCH}..."
    log_info "Build root: ${BUILD_ROOT}"
    
    create_dirs
    
    # Download dependencies
    download_ndk
    download_zlib
    download_gnulib
    download_elfutils
    download_libbpf
    
    # Verify toolchain exists
    if [ ! -f "${CC}" ]; then
        log_error "Compiler not found: ${CC}"
        exit 1
    fi
    
    # Generate gnulib-based library sources
    generate_argp_sources
    generate_obstack_sources
    
    # Build in order (dependencies first)
    build_zlib
    build_argp
    build_obstack
    build_elfutils
    build_libbpf
    
    # Package
    package_sdk
    
    # Summary
    print_summary
}

main "$@"
