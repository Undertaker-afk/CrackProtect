#include "NetworkProtection.h"
#include "../../core/Resolver.h"
#include "../../core/Hashing.h"
#include <wincrypt.h>
#include <string>

namespace IronLock::Modules::Network {

using namespace IronLock::Core;

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

} // namespace IronLock::Modules::Network
