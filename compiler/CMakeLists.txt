cmake_minimum_required(VERSION 3.15)
project(IronLockCompiler LANGUAGES CXX)

add_executable(ironlock-cl main.cpp)
target_compile_features(ironlock-cl PRIVATE cxx_std_17)
