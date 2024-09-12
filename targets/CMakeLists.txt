#
# Add debugging compile options for analysis.
#
add_compile_options(-g3)
# NOTE: This `-O2` is crucial for preventing eBPF program verification errors.
add_compile_options(-O2)

#
# Build files for eBPF programs.
#
find_package(ZLIB REQUIRED) # required by `FindBpfObject.cmake`
find_package(BpfObject REQUIRED)

#
# Configure the include directories.
#
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PROJECT_DIR)
cmake_path(SET S2E_GUEST_COMMON_INCLUDE_DIR "${PROJECT_DIR}/src/s2e/guest/common/include")
include_directories(
    ${S2E_GUEST_COMMON_INCLUDE_DIR}
)

#
# Add target programs to compile
#

set(KERNEL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/kernel)
FILE(GLOB_RECURSE KERNEL_SRCS CONFIGURE_DEPENDS ${KERNEL_DIR}/*.cpp)
foreach(KERNEL_SRC ${KERNEL_SRCS})
    get_filename_component(STEM ${KERNEL_SRC} NAME_WE)
    add_executable(kernel-${STEM} ${KERNEL_SRC} $<TARGET_OBJECTS:_logger> $<TARGET_OBJECTS:_net>)
    target_link_libraries(kernel-${STEM} PRIVATE _logger _net)
endforeach()

set(USER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/user)
FILE(GLOB_RECURSE USERSPACE_APPS CONFIGURE_DEPENDS ${USER_DIR}/*.cpp)
foreach(USERSPACE_APP ${USERSPACE_APPS})
    get_filename_component(STEM ${USERSPACE_APP} NAME_WE)
    add_executable(user-${STEM} ${USERSPACE_APP} $<TARGET_OBJECTS:_logger> $<TARGET_OBJECTS:_usernet>)
    target_link_libraries(user-${STEM} PRIVATE _logger _usernet)
endforeach()

set(EBPF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ebpf)
FILE(GLOB_RECURSE BPF_SRC_FILES CONFIGURE_DEPENDS ${EBPF_DIR}/*.bpf.c)
foreach(BPF_SRC_FILE ${BPF_SRC_FILES})
    get_filename_component(BPF_STEM ${BPF_SRC_FILE} NAME_WE)
    bpf_object(${BPF_STEM} ${BPF_SRC_FILE})
    add_executable(ebpf-${BPF_STEM} ${EBPF_DIR}/${BPF_STEM}.c)
    target_link_libraries(ebpf-${BPF_STEM} PUBLIC ${BPF_STEM}_skel)
endforeach()

# set(DPDK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dpdk)
# FILE(GLOB DPDK_APPS CONFIGURE_DEPENDS ${DPDK_DIR}/*.c ${DPDK_DIR}/*.cpp)
# foreach(DPDK_APP ${DPDK_APPS})
#     get_filename_component(STEM ${DPDK_APP} NAME_WE)
#     add_executable(dpdk-${STEM} ${DPDK_APP} $<TARGET_OBJECTS:_logger> $<TARGET_OBJECTS:_net>)
#     target_link_libraries(dpdk-${STEM} PRIVATE dpdk _logger _net)
# endforeach()
