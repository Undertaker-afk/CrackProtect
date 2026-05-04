cmake_minimum_required(VERSION 3.15)
project(IronLock VERSION 1.0.0 LANGUAGES C CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    message(FATAL_ERROR "This project requires MSVC or Clang-cl on Windows.")
endif()

include_directories(include)
include_directories(src)

# Core Foundation
set(CORE_SOURCES
    src/core/Crypto.cpp
    src/core/Syscalls.cpp
    src/core/Resolver.cpp
    src/core/Utils.cpp
    src/core/Response.cpp
    src/core/Audit.cpp
    src/core/Randomizer.cpp
)

# Anti-Debug
set(ANTIDEBUG_SOURCES
    src/modules/anti_debug/AntiDebug_User.cpp
    src/modules/anti_debug/AntiDebug_Kernel.cpp
)

# Anti-VM
set(ANTIVM_SOURCES
    src/modules/anti_vm/VMDetect_Generic.cpp
)

# Sandbox
set(SANDBOX_SOURCES
    src/modules/sandbox/SandboxDetect.cpp
)

# Tools
set(TOOLS_SOURCES
    src/modules/tools/ToolDetect.cpp
)

# Memory & Integrity
set(MEMORY_SOURCES
    src/modules/memory/Integrity.cpp
    src/modules/memory/BaitFunctions.cpp
)

# Network
set(NETWORK_SOURCES
    src/modules/network/NetworkProtection.cpp
)

# Obfuscation & VM
set(OBFUSCATION_SOURCES
    src/modules/obfuscation/ControlFlow.cpp
    src/modules/vm/VirtualMachine.cpp
)

# Assemble all sources
set(SDK_SOURCES
    src/IronLock.cpp
    ${CORE_SOURCES}
    ${ANTIDEBUG_SOURCES}
    ${ANTIVM_SOURCES}
    ${SANDBOX_SOURCES}
    ${TOOLS_SOURCES}
    ${MEMORY_SOURCES}
    ${NETWORK_SOURCES}
    ${OBFUSCATION_SOURCES}
)

# Library
add_library(IronLock STATIC ${SDK_SOURCES})

# Demo App
add_executable(IronLockDemo examples/main.cpp)
target_link_libraries(IronLockDemo IronLock)
