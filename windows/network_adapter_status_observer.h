#ifndef WIREGUARD_DART_NETWORK_ADAPTER_STATUS_OBSERVER_H
#define WIREGUARD_DART_NETWORK_ADAPTER_STATUS_OBSERVER_H

#include <flutter/encodable_value.h>
#include <flutter/event_channel.h>

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// Windows API include order is important to avoid conflicts
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

namespace spdlog {
class logger;
} // namespace spdlog

namespace wireguard_dart {

class NetworkAdapterStatusObserver : public flutter::StreamHandler<flutter::EncodableValue> {
public:
  NetworkAdapterStatusObserver();
  virtual ~NetworkAdapterStatusObserver();

  void StartObserving(const NET_LUID &luid);
  void StopObserving(const NET_LUID &luid);
  void StopAllObserving();

  bool IsMonitoring(const NET_LUID &luid) const;

protected:
  virtual std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>>
  OnListenInternal(const flutter::EncodableValue *arguments,
                   std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> &&events) override;

  virtual std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>>
  OnCancelInternal(const flutter::EncodableValue *arguments) override;

private:
  std::optional<NET_LUID> GetMonitoredAdapter(const NET_LUID &luid) const;

  // Static callback for Windows API
  static VOID CALLBACK IpInterfaceChangeCallback(PVOID caller_context, PMIB_IPINTERFACE_ROW row,
                                                 MIB_NOTIFICATION_TYPE notification_type);

  void HandleInterfaceChange(const NET_LUID &luid, MIB_NOTIFICATION_TYPE notification_type);
  void NotifyStatusChange(const NET_LUID &luid, const std::string &status);
  std::string GetInterfaceStatus(const NET_LUID &luid) const;
  void Cleanup();

  mutable std::mutex adapters_mutex_;
  std::vector<NET_LUID> monitored_adapters_;

  std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> sink_;

  // Notification handle for interface changes
  HANDLE interface_notification_handle_;
  bool notifications_registered_;

  std::shared_ptr<spdlog::logger> logger_;
};

} // namespace wireguard_dart

#endif // WIREGUARD_DART_NETWORK_ADAPTER_STATUS_OBSERVER_H
