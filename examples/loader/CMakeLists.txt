cmake_minimum_required(VERSION 3.15)
project(IronLockDemoLoader LANGUAGES CXX)

include_directories(../../include)

add_executable(IronLockLoader loader.cpp)
target_link_libraries(IronLockLoader PRIVATE IronLock)
