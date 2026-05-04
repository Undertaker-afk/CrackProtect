#pragma once
#include <cstdint>
#include <string>

namespace IronLock::Core {

class Randomizer {
public:
    static void Initialize(uint64_t seed = 0);
    static uint32_t GetNext();
    static std::string GenerateString(size_t len);

private:
    static uint64_t m_state;
};

} // namespace IronLock::Core
