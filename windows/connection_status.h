#ifndef WIREGUARD_DART_CONNECTION_STATUS_H
#define WIREGUARD_DART_CONNECTION_STATUS_H

#include <windows.h>
#include <ifdef.h>

#include <string>

namespace wireguard_dart {

enum ConnectionStatus { connected, disconnected, connecting, disconnecting, unknown };

std::string ConnectionStatusToString(const ConnectionStatus status);

ConnectionStatus ConnectionStatusFromWinSvcState(DWORD dwCurrentState);

ConnectionStatus ConnectionStatusFromIfOperStatus(IF_OPER_STATUS operStatus);

} // namespace wireguard_dart

#endif
