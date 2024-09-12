#
# build library sources
#
add_library(_logger OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/lib/logger.cpp)
target_compile_options(_logger PRIVATE -fno-omit-frame-pointer -fPIC)
target_include_directories(_logger PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_library(_net OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/lib/net.cpp)
target_include_directories(_net PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(_net PUBLIC
    PCAP::PCAP
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Common++
    PcapPlusPlus::Packet++
)

add_library(_usernet OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/lib/usernet.cpp)
target_include_directories(_usernet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(_usernet PUBLIC -g3)

#
# sender
#
add_executable(sender
    ${CMAKE_CURRENT_SOURCE_DIR}/sender.cpp
    $<TARGET_OBJECTS:_logger>
    $<TARGET_OBJECTS:_net>
)
add_dependencies(sender inotify-cpp)
target_include_directories(sender PRIVATE ${inotify_cpp_INCLUDE_DIRS})
target_link_libraries(sender PRIVATE
    _logger
    _net
    Threads::Threads
    ${inotify_cpp_LIBRARIES}
)

#
# libps
#
FILE(GLOB_RECURSE LIBPS_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libps/*.cpp)
FILE(GLOB_RECURSE LIBPS_HDRS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libps/*.hpp)
add_library(ps STATIC $<TARGET_OBJECTS:_logger> ${LIBPS_SRCS})
add_dependencies(ps sylvan)
target_compile_options(ps PRIVATE -fno-omit-frame-pointer -fPIC)
target_include_directories(ps PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(ps SYSTEM PUBLIC
    ${KLEE_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
    ${sylvan_INCLUDE_DIRS}
)
target_link_libraries(ps PRIVATE _logger cereal::cereal)
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
