#[=======================================================================[.rst:
FindDPDK
----------

Finds the DPDK library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``dpdk``
  The DPDK library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``DPDK_FOUND``
  True if the system has the DPDK library.
``DPDK_INCLUDE_DIRS``
  Include directories needed to use DPDK.
``DPDK_LIBRARIES``
  Libraries needed to link to DPDK.

#]=======================================================================]

find_package(PkgConfig REQUIRED)

list(APPEND PKG_CONFIG_ARGN "--static")
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

if(DPDK_FOUND AND NOT TARGET dpdk)
    add_library(dpdk INTERFACE)
    target_include_directories(dpdk SYSTEM INTERFACE ${DPDK_INCLUDE_DIRS})
    target_compile_options(dpdk INTERFACE ${DPDK_CFLAGS})
    target_link_libraries(dpdk INTERFACE -static ${DPDK_LDFLAGS})
endif()
