#
# sender
#
add_executable(sender $<TARGET_OBJECTS:mimesis_libs> ${SRC_DIR}/sender.cpp)
add_dependencies(sender inotify-cpp)
target_include_directories(sender PRIVATE ${inotify_cpp_INCLUDE_DIRS})
target_link_libraries(sender PRIVATE
    mimesis_libs
    Threads::Threads
    ${inotify_cpp_LIBRARIES}
)

#
# set capability for sender
#
# add_custom_target(setcap_sender ALL
#     sudo setcap "cap_sys_admin+pe cap_net_admin+pe cap_net_raw+pe cap_sys_ptrace+pe" sender
#     DEPENDS sender
# )

#
# libps
#
add_subdirectory(libps)
