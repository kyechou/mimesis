#
# build sender
#
add_executable(sender $<TARGET_OBJECTS:mimesis_libs> ${SRC_DIR}/sender.cpp)
target_link_libraries(sender PRIVATE
    mimesis_libs
    Threads::Threads
    inotify-cpp-static
)
