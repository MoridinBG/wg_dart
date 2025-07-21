#include "network_adapter_status_observer.h"

#include <algorithm>

#include "connection_status.h"
#include "spdlog/spdlog.h"

namespace wireguard_dart {

NetworkAdapterStatusObserver::NetworkAdapterStatusObserver()
    : interface_notification_handle_(nullptr), notifications_registered_(false) {
  try {
    logger_ = spdlog::get("wireguard_dart");
    if (!logger_) {
      logger_ = spdlog::default_logger();
      logger_->info("NetworkAdapterStatusObserver initialized with default logger");
    }
  } catch (const std::exception &e) {
    // Fallback to default logger if initialization fails
    logger_ = spdlog::default_logger();
    logger_->warn("Failed to initialize named logger, using default: {}", e.what());
  }
}

NetworkAdapterStatusObserver::~NetworkAdapterStatusObserver() { Cleanup(); }

void NetworkAdapterStatusObserver::StartObserving(const NET_LUID &luid) {
  std::lock_guard<std::mutex> lock(adapters_mutex_);

  auto found_adapter = GetMonitoredAdapter(luid);

  if (found_adapter.has_value()) {
    logger_->info("Already monitoring adapter with LUID: {}", luid.Value);
    return;
  }

  // Register for Windows API notifications if not already registered
  if (!notifications_registered_) {
    DWORD result =
        NotifyIpInterfaceChange(AF_UNSPEC, IpInterfaceChangeCallback, this, FALSE, &interface_notification_handle_);
    if (result != NO_ERROR) {
      logger_->error("Failed to register for interface change notifications: {}", result);
      return;
    }

    notifications_registered_ = true;
    logger_->info("Registered for global network change notifications");
  }

  monitored_adapters_.push_back(luid);

  logger_->info("Started monitoring adapter with LUID: {}", luid.Value);

  // Send initial status
  if (sink_) {
    std::string current_status = GetInterfaceStatus(luid);
    NotifyStatusChange(luid, current_status);
  }
}

void NetworkAdapterStatusObserver::StopObserving(const NET_LUID &luid) {
  std::lock_guard<std::mutex> lock(adapters_mutex_);

  auto it = std::find_if(monitored_adapters_.begin(), monitored_adapters_.end(),
                         [&luid](const NET_LUID &monitored_luid) { return monitored_luid.Value == luid.Value; });

  if (it != monitored_adapters_.end()) {
    logger_->info("Stopped monitoring adapter with LUID: {}", luid.Value);

    monitored_adapters_.erase(it);

    // If no more adapters are being monitored, clean up global notifications
    if (monitored_adapters_.empty() && notifications_registered_) {
      if (interface_notification_handle_) {
        CancelMibChangeNotify2(interface_notification_handle_);
        interface_notification_handle_ = nullptr;
      }
      notifications_registered_ = false;
      logger_->info("Unregistered global network change notifications");
    }
  }
}

void NetworkAdapterStatusObserver::StopAllObserving() {
  std::lock_guard<std::mutex> lock(adapters_mutex_);

  monitored_adapters_.clear();

  if (notifications_registered_) {
    if (interface_notification_handle_) {
      CancelMibChangeNotify2(interface_notification_handle_);
      interface_notification_handle_ = nullptr;
    }
    notifications_registered_ = false;
    logger_->info("Stopped monitoring all adapters and unregistered notifications");
  }
}

bool NetworkAdapterStatusObserver::IsMonitoring(const NET_LUID &luid) const {
  std::lock_guard<std::mutex> lock(adapters_mutex_);

  auto found_adapter = GetMonitoredAdapter(luid);
  return found_adapter.has_value();
}

VOID CALLBACK NetworkAdapterStatusObserver::IpInterfaceChangeCallback(PVOID caller_context, PMIB_IPINTERFACE_ROW row,
                                                                      MIB_NOTIFICATION_TYPE notification_type) {
  auto *observer = static_cast<NetworkAdapterStatusObserver *>(caller_context);
  if (!observer || !row) {
    return;
  }

  observer->HandleInterfaceChange(row->InterfaceLuid, notification_type);
}

void NetworkAdapterStatusObserver::HandleInterfaceChange(const NET_LUID &luid,
                                                         MIB_NOTIFICATION_TYPE notification_type) {
  // Lock only while looking up the adapter
  // and release the lock while potentially blocking while reading adapter status and notifying flutter
  bool is_monitoring;
  {
    std::lock_guard<std::mutex> lock(adapters_mutex_);
    is_monitoring = GetMonitoredAdapter(luid).has_value();
  }

  if (is_monitoring) {
    std::string status = GetInterfaceStatus(luid);
    logger_->info("Interface change for adapter LUID {}: {} -> {}", luid.Value, static_cast<int>(notification_type),
                  status);
    NotifyStatusChange(luid, status);
  }
}

void NetworkAdapterStatusObserver::NotifyStatusChange(const NET_LUID &luid, const std::string &status) {
  if (sink_) {
    flutter::EncodableMap status_map;
    status_map[flutter::EncodableValue("status")] = flutter::EncodableValue(status);
    status_map[flutter::EncodableValue("luid")] = flutter::EncodableValue(static_cast<int64_t>(luid.Value));

    sink_->Success(flutter::EncodableValue(status_map));
  }
}

std::string NetworkAdapterStatusObserver::GetInterfaceStatus(const NET_LUID &luid) {
  MIB_IF_ROW2 if_row;
  if_row.InterfaceLuid = luid;

  DWORD result = GetIfEntry2(&if_row);
  if (result != NO_ERROR) {
    logger_->error("Failed to get interface entry: {}", result);
    return ConnectionStatusToString(ConnectionStatus::unknown);
  }

  auto if_oper_status = ConnectionStatusFromIfOperStatus(if_row.OperStatus);
  return ConnectionStatusToString(ConnectionStatus::connected);
}

void NetworkAdapterStatusObserver::Cleanup() { StopAllObserving(); }

std::optional<NET_LUID> NetworkAdapterStatusObserver::GetMonitoredAdapter(const NET_LUID &luid) const {
  auto it = std::find_if(monitored_adapters_.begin(), monitored_adapters_.end(),
                         [&luid](const NET_LUID &monitored_luid) { return monitored_luid.Value == luid.Value; });
  return (it != monitored_adapters_.end()) ? std::optional<NET_LUID>(*it) : std::nullopt;
}

std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>>
NetworkAdapterStatusObserver::OnListenInternal(const flutter::EncodableValue *arguments,
                                               std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> &&events) {
  sink_ = std::move(events);
  return nullptr;
}

std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>>
NetworkAdapterStatusObserver::OnCancelInternal(const flutter::EncodableValue *arguments) {
  if (sink_) {
    sink_.reset();
  }
  return nullptr;
}

} // namespace wireguard_dart
