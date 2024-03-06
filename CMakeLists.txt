cmake_minimum_required(VERSION 3.13)
project(Mimesis VERSION 0.1 HOMEPAGE_URL https://github.com/kyechou/mimesis LANGUAGES C CXX)
include("ExternalProject")
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
set(CMAKE_C_FLAGS_RELEASE   "-O3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_C_FLAGS_RELWITHDEBINFO   "-O3 -g")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O3 -g")
set(CMAKE_C_FLAGS_DEBUG   "-DENABLE_DEBUG -g3 -fsanitize=address -fno-omit-frame-pointer -fno-common")
set(CMAKE_CXX_FLAGS_DEBUG "-DENABLE_DEBUG -g3 -fsanitize=address -fno-omit-frame-pointer -fno-common")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")
if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

#
# configure the sources and directories
#
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

#
# build library sources
#
FILE(GLOB_RECURSE LIB_SRCS CONFIGURE_DEPENDS ${SRC_DIR}/lib/*.cpp)
add_library(mimesis_libs OBJECT ${LIB_SRCS})
target_include_directories(mimesis_libs PUBLIC ${SRC_DIR})

#
# build sender
#
add_executable(sender $<TARGET_OBJECTS:mimesis_libs> ${SRC_DIR}/sender.cpp)
target_link_libraries(sender PRIVATE mimesis_libs)

#
# build target programs
#
add_subdirectory(targets)
