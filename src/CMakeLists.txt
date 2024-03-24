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
# libps
#
add_subdirectory(libps)
