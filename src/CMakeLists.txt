#
# sender
#
add_executable(sender $<TARGET_OBJECTS:mimesis_libs> ${SRC_DIR}/sender.cpp)
target_link_libraries(sender PRIVATE
    mimesis_libs
    inotify-cpp-static
    Threads::Threads
)

#
# set capability for sender
#
add_custom_target(setcap_sender ALL
    sudo setcap "cap_sys_admin+pe cap_net_admin+pe cap_net_raw+pe cap_sys_ptrace+pe" sender
    DEPENDS sender
)

#
# libps
#
add_library(ps $<TARGET_OBJECTS:mimesis_libs> ${SRC_DIR}/packet_set.cpp)
target_include_directories(ps PUBLIC ${SRC_DIR})
target_include_directories(ps PRIVATE ${LLVM_INCLUDE_DIRS})
target_link_libraries(ps PRIVATE
    mimesis_libs
    klee
)

#
# install libps (to be used for S2E)
#
install(TARGETS ps DESTINATION lib)
install(FILES ${SRC_DIR}/packet_set.hpp DESTINATION include)
