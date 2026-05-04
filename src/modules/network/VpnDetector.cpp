#include "NetworkProtection.h"
#include "../../core/Resolver.h"
#include "../../core/Hashing.h"
#include <vector>
#include <string>
#include <iphlpapi.h>

namespace IronLock::Modules::Network {

using namespace IronLock::Core;

bool IsVpnPresent() {
    auto pGetAdaptersAddresses = Resolver::GetExport<decltype(&GetAdaptersAddresses)>(Hashing::HashStringW(L"iphlpapi.dll"), Hashing::HashString("GetAdaptersAddresses"));
    if (!pGetAdaptersAddresses) return false;

    ULONG size = 0;
    pGetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    if (size == 0) return false;

    std::vector<BYTE> buf(size);
    PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)buf.data();
    if (pGetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &size) == ERROR_SUCCESS) {
        while (addrs) {
            std::wstring desc(addrs->Description);
            if (desc.find(L"TAP") != std::wstring::npos || desc.find(L"VPN") != std::wstring::npos || desc.find(L"Wintun") != std::wstring::npos) {
                return true;
            }
            addrs = addrs->Next;
        }
    }
    return false;
}

} // namespace IronLock::Modules::Network
