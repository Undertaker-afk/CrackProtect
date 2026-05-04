#include "Randomizer.h"
#include <intrin.h>

namespace IronLock::Core {

uint64_t Randomizer::m_state = 0;

void Randomizer::Initialize(uint64_t seed) {
    if (seed == 0) {
        m_state = __rdtsc();
    } else {
        m_state = seed;
    }
}

// SplitMix64 or similar robust LCG
uint32_t Randomizer::GetNext() {
    uint64_t z = (m_state += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return (uint32_t)(z ^ (z >> 31));
}

std::string Randomizer::GenerateString(size_t len) {
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string res;
    res.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        res += charset[GetNext() % (sizeof(charset) - 1)];
    }
    return res;
}

} // namespace IronLock::Core
