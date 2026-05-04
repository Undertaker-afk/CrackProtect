#include "NetworkProtection.h"
#include "../../core/Utils.h"
#include "../../core/Resolver.h"
#include "../../core/Syscalls.h"
#include "../../core/Hashing.h"
#include <vector>
#include <string>
#include <iphlpapi.h>

namespace IronLock::Modules::Network {

using namespace IronLock::Core;

bool IsSystemProxyHijacked() {
    // Manually resolve registry functions if possible, or use syscalls for direct registry access
    // For now, we use the Resolver to get the functions
    typedef LSTATUS(WINAPI* tRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LSTATUS(WINAPI* tRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    typedef LSTATUS(WINAPI* tRegCloseKey)(HKEY);

    auto pRegOpenKeyExW = Resolver::GetExport<tRegOpenKeyExW>(Hashing::HashStringW(L"advapi32.dll"), Hashing::HashString("RegOpenKeyExW"));
    auto pRegQueryValueExW = Resolver::GetExport<tRegQueryValueExW>(Hashing::HashStringW(L"advapi32.dll"), Hashing::HashString("RegQueryValueExW"));
    auto pRegCloseKey = Resolver::GetExport<tRegCloseKey>(Hashing::HashStringW(L"advapi32.dll"), Hashing::HashString("RegCloseKey"));

    if (!pRegOpenKeyExW || !pRegQueryValueExW || !pRegCloseKey) return false;

    HKEY hKey;
    if (pRegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enabled = 0;
        DWORD size = sizeof(enabled);
        if (pRegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&enabled, &size) == ERROR_SUCCESS) {
            if (enabled) {
                wchar_t proxy[256];
                size = sizeof(proxy);
                if (pRegQueryValueExW(hKey, L"ProxyServer", NULL, NULL, (LPBYTE)proxy, &size) == ERROR_SUCCESS) {
                    std::wstring p(proxy);
                    if (p.find(L"127.0.0.1") != std::wstring::npos || p.find(L"localhost") != std::wstring::npos) {
                        pRegCloseKey(hKey);
                        return true;
                    }
                }
            }
        }
        pRegCloseKey(hKey);
    }
    return false;
}

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

bool IsMitmCertificateInstalled() {
    auto pCertOpenSystemStoreW = Resolver::GetExport<decltype(&CertOpenSystemStoreW)>(Hashing::HashStringW(L"crypt32.dll"), Hashing::HashString("CertOpenSystemStoreW"));
    auto pCertEnumCertificatesInStore = Resolver::GetExport<decltype(&CertEnumCertificatesInStore)>(Hashing::HashStringW(L"crypt32.dll"), Hashing::HashString("CertEnumCertificatesInStore"));
    auto pCertGetNameStringW = Resolver::GetExport<decltype(&CertGetNameStringW)>(Hashing::HashStringW(L"crypt32.dll"), Hashing::HashString("CertGetNameStringW"));
    auto pCertCloseStore = Resolver::GetExport<decltype(&CertCloseStore)>(Hashing::HashStringW(L"crypt32.dll"), Hashing::HashString("CertCloseStore"));

    if (!pCertOpenSystemStoreW) return false;

    HCERTSTORE hStore = pCertOpenSystemStoreW(NULL, L"ROOT");
    if (!hStore) return false;

    bool found = false;
    PCCERT_CONTEXT pCtx = NULL;
    while ((pCtx = pCertEnumCertificatesInStore(hStore, pCtx))) {
        wchar_t name[256];
        if (pCertGetNameStringW(pCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, 256)) {
            std::wstring s(name);
            if (s.find(L"Fiddler") != std::wstring::npos || s.find(L"Charles") != std::wstring::npos || s.find(L"PortSwigger") != std::wstring::npos) {
                found = true;
                break;
            }
        }
    }
    pCertCloseStore(hStore, 0);
    return found;
}

bool RunAllNetworkChecks() {
    return IsSystemProxyHijacked() || IsVpnPresent() || IsMitmCertificateInstalled();
}

} // namespace IronLock::Modules::Network
