#[=======================================================================[.rst:
FindLLVM
----------

Finds the LLVM library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``llvm``
  The LLVM library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``LLVM_FOUND``
  True if the system has the LLVM library.
``LLVM_INCLUDE_DIRS``
  Include directories needed to use LLVM.
``LLVM_LIBRARIES``
  Libraries needed to link to LLVM.

#]=======================================================================]

find_package(LLVM REQUIRED CONFIG PATHS ${CMAKE_SOURCE_DIR}/s2e/build/llvm-release/lib/cmake/llvm NO_DEFAULT_PATH)

set(LLVM_VERSION ${LLVM_PACKAGE_VERSION})
set(LLVM_INCLUDE_DIRS ${LLVM_INCLUDE_DIR})
set(LLVM_LIBRARIES ${LLVM_AVAILABLE_LIBS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LLVM
    FOUND_VAR LLVM_FOUND
    REQUIRED_VARS LLVM_LIBRARIES
    VERSION_VAR LLVM_VERSION)

if(LLVM_FOUND AND NOT TARGET llvm)
    add_library(llvm INTERFACE)
    target_include_directories(llvm SYSTEM INTERFACE ${LLVM_INCLUDE_DIRS})
    target_link_libraries(llvm INTERFACE ${LLVM_LIBRARIES})
endif()
