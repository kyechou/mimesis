FILE(GLOB_RECURSE LIBPS_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
FILE(GLOB_RECURSE LIBPS_HDRS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)

add_library(ps $<TARGET_OBJECTS:mimesis_libs> ${LIBPS_SRCS})
target_include_directories(ps PUBLIC ${SRC_DIR})
target_include_directories(ps PRIVATE ${LLVM_INCLUDE_DIRS})
target_link_libraries(ps PRIVATE
    mimesis_libs
    klee
)

install(TARGETS ps DESTINATION lib)
install(FILES ${LIBPS_HDRS} DESTINATION include/libps)
