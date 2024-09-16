ExternalProject_Add(libxdp
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xdp-tools
    CONFIGURE_COMMAND ./configure
    BUILD_COMMAND make -s
        DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/install
        libxdp libxdp_install
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/install/usr/local/lib/libxdp.a
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    STEP_TARGETS build
)

set(libxdp_VERSION "1.4.3" PARENT_SCOPE)
set(libxdp_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/install/usr/local/include PARENT_SCOPE)
set(libxdp_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/install/usr/local/lib/libxdp.a PARENT_SCOPE)
