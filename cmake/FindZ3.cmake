#[=======================================================================[.rst:
FindZ3
----------

Finds the Z3 library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``z3``
The Z3 library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``Z3_FOUND``
  True if the system has the Z3 library.
``Z3_INCLUDE_DIRS``
  Include directories needed to use Z3.
``Z3_LIBRARIES``
  Libraries needed to link to Z3.

#]=======================================================================]

set(Z3_VERSION 4.7.1)
set(Z3_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/s2e/install/include)
set(Z3_LIBRARIES ${CMAKE_SOURCE_DIR}/s2e/install/lib/libz3.a;gomp)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Z3
    FOUND_VAR Z3_FOUND
    REQUIRED_VARS Z3_INCLUDE_DIRS Z3_LIBRARIES
    VERSION_VAR Z3_VERSION)

if(Z3_FOUND AND NOT TARGET z3)
    add_library(z3 INTERFACE)
    target_include_directories(z3 SYSTEM INTERFACE ${Z3_INCLUDE_DIRS})
    target_link_libraries(z3 INTERFACE ${Z3_LIBRARIES})
endif()
