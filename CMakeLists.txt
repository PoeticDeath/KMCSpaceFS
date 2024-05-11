cmake_minimum_required(VERSION 3.15)

project(KMCSpaceFS VERSION 0.0.1)

add_compile_options("-O2")

# KMCSpaceFS.sys

set(SRC_FILES
    src/KMCSpaceFS.c
    src/registry.c
    src/pnp.c
    src/search.c
    src/volume.c
    src/boot.c
    src/devctrl.c
    src/create.c
    src/CSpaceFS.c
    src/dirctrl.c
    src/fileinfo.c
    src/read.c
    src/security.c
    src/write.c
    src/fsctl.c
    src/Sha3.c
    src/Dict.c
    ${CMAKE_CURRENT_BINARY_DIR}/KMCSpaceFS.rc)

if(MSVC) # cmake bug 15170
    if(MSVC_C_ARCHITECTURE_ID STREQUAL "X86")
        set(CMAKE_SYSTEM_PROCESSOR "x86")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "x64")
        set(CMAKE_SYSTEM_PROCESSOR "x86_64")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "ARMV7")
        set(CMAKE_SYSTEM_PROCESSOR "arm")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "ARM64")
		set(CMAKE_SYSTEM_PROCESSOR "aarch64")
    endif()
endif()

# Work around bug in MSVC version of cmake - see https://gitlab.kitware.com/cmake/cmake/-/merge_requests/4257
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreaded         "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDLL      "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebug    "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebugDLL "")

set(CMAKE_ASM_MASM_FLAGS "/Zd")

configure_file(src/KMCSpaceFS.rc.in KMCSpaceFS.rc)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_definitions(-D_AMD64_)
    set(MS_ARCH "x64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    add_definitions(-D_X86_)
    set(MS_ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    add_definitions(-D_ARM_)
    set(MS_ARCH "arm")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    add_definitions(-D_ARM64_)
    set(MS_ARCH "arm64")
endif()

if(MSVC)
    include_directories("$ENV{WindowsSdkDir}Include\\$ENV{WindowsSDKLibVersion}km")
    link_directories("$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    include_directories("${CMAKE_FIND_ROOT_PATH}/usr/include/ddk")
endif()

add_library(KMCSpaceFS SHARED ${SRC_FILES})

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-D_DEBUG)
endif()

if(NOT MSVC)
    target_compile_options(KMCSpaceFS PUBLIC -U__NO_INLINE__)
    add_definitions(-D__USE_MINGW_ANSI_STDIO=0)
endif()

target_compile_definitions(KMCSpaceFS PUBLIC _KERNEL_MODE WIN9X_COMPAT_SPINLOCK)

if(MSVC)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        target_compile_options(KMCSpaceFS PUBLIC /Gz) # stdcall
    endif()

    target_link_libraries(KMCSpaceFS ntoskrnl hal)

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        target_link_libraries(KMCSpaceFS bufferoverflowfastfailk)
    else()
        target_link_libraries(KMCSpaceFS BufferOverflowK)
    endif()

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
        target_link_libraries(KMCSpaceFS armrt)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        target_link_libraries(KMCSpaceFS arm64rt)
    endif()

    target_link_libraries(KMCSpaceFS rtlver)
    target_link_options(KMCSpaceFS PUBLIC /SUBSYSTEM:NATIVE /NODEFAULTLIB /MANIFEST:NO /Driver /ENTRY:DriverEntry)

    # strip out flags for MSVC's runtime checks
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
else()
    target_compile_options(KMCSpaceFS PUBLIC -Wall -Werror-implicit-function-declaration -Werror=incompatible-pointer-types -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(KMCSpaceFS PUBLIC -Werror=cast-function-type -Wold-style-declaration)
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(KMCSpaceFS PUBLIC -Wno-pragma-pack) # ignore warning in mingw headers
    endif()

    target_link_libraries(KMCSpaceFS ntoskrnl hal gcc)
    target_link_options(KMCSpaceFS PUBLIC -nostdlib -Wl,--subsystem,native -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 -Wl,--exclude-all-symbols)

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        target_link_options(KMCSpaceFS PUBLIC -Wl,--entry,_DriverEntry@8)
    else()
        target_link_options(KMCSpaceFS PUBLIC -Wl,--entry,DriverEntry)
    endif()
endif()

set_target_properties(KMCSpaceFS PROPERTIES PREFIX "")
set_target_properties(KMCSpaceFS PROPERTIES SUFFIX ".sys")

# --------------------------------------

# install

install(TARGETS KMCSpaceFS DESTINATION bin)
