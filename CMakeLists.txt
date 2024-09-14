cmake_minimum_required(VERSION 3.22)

#
# cmake configure options
#
option(BUILD_TESTS "Build tests" ON)

#
# vcpkg manifest mode
#
set(VCPKG_MANIFEST_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/depends"
    CACHE STRING "Path to vcpkg manifest directory")
if(BUILD_TESTS)
    list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()
set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/depends/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

#
# project
#
project(Mimesis VERSION 0.0.1 HOMEPAGE_URL https://github.com/kyechou/mimesis LANGUAGES C CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#
# compile options
#
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

#
# release/debug compile options
#
set(CMAKE_C_FLAGS_RELEASE          "-O3 -g")
set(CMAKE_CXX_FLAGS_RELEASE        "-O3 -g")
set(CMAKE_C_FLAGS_RELWITHDEBINFO   "-O2 -g")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
set(CMAKE_C_FLAGS_DEBUG   "-DENABLE_DEBUG -g3 -fsanitize=address -fno-omit-frame-pointer -fno-common")
set(CMAKE_CXX_FLAGS_DEBUG "-DENABLE_DEBUG -g3 -fsanitize=address -fno-omit-frame-pointer -fno-common")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")
if("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

#
# third-party libraries
#
include("ExternalProject")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
add_subdirectory(third_party/bpftool EXCLUDE_FROM_ALL)
add_subdirectory(third_party/libbpf EXCLUDE_FROM_ALL)
add_subdirectory(third_party/inotify-cpp EXCLUDE_FROM_ALL)
add_subdirectory(third_party/sylvan EXCLUDE_FROM_ALL)
find_package(Threads REQUIRED)
find_package(boost_program_options CONFIG REQUIRED)
find_package(cereal CONFIG REQUIRED)
find_package(PcapPlusPlus REQUIRED)
# find_package(DPDK REQUIRED)
find_package(KLEE REQUIRED) # built in s2e tree
find_package(LLVM REQUIRED) # built in s2e tree
find_package(Z3 REQUIRED)   # built in s2e tree

#
# build libraries and programs
#
add_subdirectory(src)
add_subdirectory(targets)

#
# build tests targets
#
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
