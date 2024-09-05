#
# Add debugging compile options for analysis.
#
add_compile_options(-g3)

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

add_executable(hello-world ${CMAKE_CURRENT_SOURCE_DIR}/hello-world.cpp)

set(KERNEL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/kernel)
FILE(GLOB_RECURSE KERNEL_SRCS CONFIGURE_DEPENDS ${KERNEL_DIR}/*.cpp)
foreach(KERNEL_SRC ${KERNEL_SRCS})
    get_filename_component(STEM ${KERNEL_SRC} NAME_WE)
    add_executable(kernel-${STEM} ${KERNEL_SRC} $<TARGET_OBJECTS:_logger> $<TARGET_OBJECTS:_net>)
    target_link_libraries(kernel-${STEM} PRIVATE _logger _net)
endforeach()

set(USER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/user)
FILE(GLOB USERSPACE_APPS CONFIGURE_DEPENDS ${USER_DIR}/*.cpp)
foreach(USERSPACE_APP ${USERSPACE_APPS})
    get_filename_component(STEM ${USERSPACE_APP} NAME_WE)
    add_executable(user-${STEM} ${USERSPACE_APP} $<TARGET_OBJECTS:_logger> $<TARGET_OBJECTS:_usernet>)
    # target_link_libraries(user-${STEM} PRIVATE -static _logger _usernet)
    target_link_libraries(user-${STEM} PRIVATE _logger _usernet)
endforeach()

# set(DPDK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dpdk)
# FILE(GLOB DPDK_APPS CONFIGURE_DEPENDS ${DPDK_DIR}/*.c ${DPDK_DIR}/*.cpp)
# foreach(DPDK_APP ${DPDK_APPS})
#     get_filename_component(STEM ${DPDK_APP} NAME_WE)
#     add_executable(dpdk-${STEM} ${DPDK_APP} $<TARGET_OBJECTS:_logger> $<TARGET_OBJECTS:_net>)
#     target_link_libraries(dpdk-${STEM} PRIVATE dpdk _logger _net)
# endforeach()
