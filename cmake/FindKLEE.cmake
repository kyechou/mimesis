#[=======================================================================[.rst:
FindKLEE
----------

Finds the KLEE library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``klee``
  The KLEE library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``KLEE_FOUND``
  True if the system has the KLEE library.
``KLEE_INCLUDE_DIRS``
  Include directories needed to use KLEE.
``KLEE_LIBRARIES``
  Libraries needed to link to KLEE.

#]=======================================================================]

find_package(KLEE REQUIRED CONFIG PATHS ${CMAKE_SOURCE_DIR}/s2e/s2e/build/klee-release NO_DEFAULT_PATH)

set(KLEE_FOUND ON)
set(KLEE_VERSION ${KLEE_PACKAGE_VERSION})
set(KLEE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/src/s2e/klee/include")
set(KLEE_INCLUDE_DIRS ${KLEE_INCLUDE_DIR})
FILE(GLOB_RECURSE KLEE_LIBRARIES CONFIGURE_DEPENDS ${KLEE_LIBRARY_DIR}/*.a)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(KLEE
    FOUND_VAR KLEE_FOUND
    REQUIRED_VARS KLEE_LIBRARIES
    VERSION_VAR KLEE_VERSION)

if(KLEE_FOUND AND NOT TARGET klee)
    add_library(klee INTERFACE)
    target_include_directories(klee SYSTEM INTERFACE ${KLEE_INCLUDE_DIRS})
    target_link_libraries(klee INTERFACE ${KLEE_LIBRARIES})
endif()
