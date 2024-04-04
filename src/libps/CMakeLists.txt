FILE(GLOB_RECURSE LIBPS_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
FILE(GLOB_RECURSE LIBPS_HDRS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)

add_library(ps STATIC ${LIBPS_SRCS})
add_dependencies(ps sylvan)
target_compile_options(ps PRIVATE -fno-omit-frame-pointer -fPIC)
target_include_directories(ps PUBLIC ${SRC_DIR})
target_include_directories(ps SYSTEM PUBLIC
    ${KLEE_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
    ${sylvan_INCLUDE_DIRS}
)
target_link_libraries(ps PUBLIC
    klee
    llvm
    z3
    ${sylvan_LIBRARIES}
)

# Install libps headers and libraries
install(TARGETS ps DESTINATION lib)
install(FILES ${LIBPS_HDRS} DESTINATION include/libps)

# Install sylvan headers and libraries. This is necessary for linking with S2E.
install(FILES ${sylvan_LIBRARIES} DESTINATION lib)
foreach(incdir ${sylvan_INCLUDE_DIRS})
    install(DIRECTORY ${incdir}/ DESTINATION include)
endforeach()
