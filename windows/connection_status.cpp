#include "connection_status.h"

#include <string>

namespace wireguard_dart {

std::string ConnectionStatusToString(const ConnectionStatus status) {
  switch (status) {
    case ConnectionStatus::connected:
      return "connected";
    case ConnectionStatus::disconnected:
      return "disconnected";
    case ConnectionStatus::connecting:
      return "connecting";
    case ConnectionStatus::disconnecting:
      return "disconnecting";
    default:
      return "unknown";
  }
}

ConnectionStatus ConnectionStatusFromIfOperStatus(IF_OPER_STATUS operStatus) {
  switch (operStatus) {
    case IfOperStatusUp:
      return ConnectionStatus::connected;
    case IfOperStatusDown:
      return ConnectionStatus::disconnected;
    case IfOperStatusTesting:
    case IfOperStatusUnknown:
    case IfOperStatusDormant:
    case IfOperStatusNotPresent:
    case IfOperStatusLowerLayerDown:
    default:
      return ConnectionStatus::unknown;
  }
}

} // namespace wireguard_dart
