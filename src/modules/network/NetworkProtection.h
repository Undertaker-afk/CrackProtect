#pragma once
#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <wincrypt.h>

namespace IronLock::Modules::Network {

bool IsHttpInterceptorPresent();
bool IsMitmCertificateInstalled();
bool IsSystemProxyHijacked();
bool IsVpnPresent();
bool IsAnonymizationNetworkActive();
bool IsPacketCaptureDriverLoaded();

bool RunAllNetworkChecks();

} // namespace IronLock::Modules::Network
