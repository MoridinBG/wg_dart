#include "wireguard_adapter.h"

#include <stdexcept>
#include <vector>

#include "wireguard_config_parser.h"
#include "wireguard_network_config.h"
#include "spdlog/spdlog.h"
#include "utils.h"

namespace wireguard_dart {

std::unique_ptr<WireguardAdapter> WireguardAdapter::Create(const std::shared_ptr<WireguardLibrary> &library,
                                                           const std::wstring &name, const std::wstring &tunnel_type) {
  if (!library || !library->IsLoaded()) {
    return nullptr;
  }

  auto adapter = std::unique_ptr<WireguardAdapter>(new WireguardAdapter(library, name));

  adapter->adapter_handle_ = library->CreateAdapter()(name.c_str(), tunnel_type.c_str(),
                                                      nullptr // Let system choose GUID
  );

  if (!adapter->adapter_handle_) {
    return nullptr;
  }

  return adapter;
}

std::unique_ptr<WireguardAdapter> WireguardAdapter::Open(const std::shared_ptr<WireguardLibrary> &library,
                                                         const std::wstring &name) {
  if (!library || !library->IsLoaded()) {
    return nullptr;
  }

  auto adapter = std::unique_ptr<WireguardAdapter>(new WireguardAdapter(library, name));

  adapter->adapter_handle_ = library->OpenAdapter()(name.c_str());

  if (!adapter->adapter_handle_) {
    return nullptr;
  }

  return adapter;
}

WireguardAdapter::WireguardAdapter(const std::shared_ptr<WireguardLibrary> &library, const std::wstring &name)
    : library_(library), name_(name) {
  // Initialize logger
  try {
    logger_ = spdlog::get("wireguard_dart");
    if (!logger_) {
      logger_ = spdlog::default_logger();
    }
  } catch (const std::exception &) {
    // Fallback to default logger if initialization fails
    logger_ = spdlog::default_logger();
  }
}

WireguardAdapter::~WireguardAdapter() {
  if (adapter_handle_ && library_ && library_->IsLoaded()) {
    library_->CloseAdapter()(adapter_handle_);
    adapter_handle_ = nullptr;
  }
}

bool WireguardAdapter::SetState(WIREGUARD_ADAPTER_STATE state) {
  if (!IsValid() || !library_->IsLoaded()) {
    return false;
  }

  return library_->SetAdapterState()(adapter_handle_, state) != FALSE;
}

WIREGUARD_ADAPTER_STATE WireguardAdapter::GetState() const {
  if (!IsValid() || !library_->IsLoaded()) {
    return WIREGUARD_ADAPTER_STATE_DOWN;
  }

  WIREGUARD_ADAPTER_STATE state;
  if (library_->GetAdapterState()(adapter_handle_, &state)) {
    return state;
  }

  return WIREGUARD_ADAPTER_STATE_DOWN;
}

bool WireguardAdapter::SetConfiguration(const WIREGUARD_INTERFACE *config, DWORD bytes) {
  if (!IsValid() || !library_->IsLoaded() || !config) {
    return false;
  }

  return library_->SetConfiguration()(adapter_handle_, config, bytes) != FALSE;
}

bool WireguardAdapter::GetLUID(NET_LUID *luid) const {
  if (!IsValid() || !library_->IsLoaded() || !luid) {
    return false;
  }

  library_->GetAdapterLuid()(adapter_handle_, luid);
  return true;
}

bool WireguardAdapter::SetLogging(WIREGUARD_ADAPTER_LOG_STATE log_state) {
  if (!IsValid() || !library_->IsLoaded()) {
    return false;
  }

  return library_->SetAdapterLogging()(adapter_handle_, log_state) != FALSE;
}

bool WireguardAdapter::ApplyConfiguration(const std::string &config_text) {
  logger_->info("Applying WireGuard configuration for adapter: {}", WideToUtf8(name_));

  if (!IsValid() || !library_->IsLoaded()) {
    logger_->error("Failed to apply configuration: adapter invalid or library not loaded");
    return false;
  }

  // Parse and store configuration
  WireguardConfigParser parser;
  if (!parser.Parse(config_text)) {
    parsed_config_.reset(); // Clear any previous config
    logger_->error("Failed to parse WireGuard configuration");
    return false;
  }

  // Calculate required buffer size
  DWORD config_size = parser.CalculateConfigurationSize();
  if (config_size == 0) {
    parsed_config_.reset();
    logger_->error("Configuration size calculation returned 0");
    return false;
  }

  // Allocate buffer and build configuration
  std::vector<BYTE> config_buffer(config_size);
  DWORD actual_size = parser.BuildConfiguration(config_buffer.data(), config_size);
  if (actual_size == 0 || actual_size != config_size) {
    parsed_config_.reset();
    logger_->error("Failed to build configuration: expected {} bytes, got {} bytes", config_size, actual_size);
    return false;
  }

  // Apply configuration to adapter
  const WIREGUARD_INTERFACE *config = reinterpret_cast<const WIREGUARD_INTERFACE *>(config_buffer.data());
  if (!SetConfiguration(config, actual_size)) {
    parsed_config_.reset();
    logger_->error("Failed to set WireGuard configuration on adapter");
    return false;
  }

  parsed_config_ = std::move(parser);

  // Set adapter state to UP after successful configuration
  if (!SetState(WIREGUARD_ADAPTER_STATE_UP)) {
    logger_->error("Failed to set adapter state to UP");
    return false;
  }

  logger_->info("Successfully applied WireGuard configuration and set adapter UP");
  return true;
}

bool WireguardAdapter::ConfigureNetworking() {
  logger_->info("Configuring network interface for adapter: {}", WideToUtf8(name_));

  if (!parsed_config_.has_value()) {
    logger_->error("No parsed configuration available for network setup");
    return false; // No config to apply
  }

  if (!IsValid()) {
    logger_->error("Adapter is not valid for network configuration");
    return false;
  }

  NET_LUID luid;
  if (!GetLUID(&luid)) {
    logger_->error("Failed to get adapter LUID for network configuration");
    return false;
  }

  // Create network config helper
  WireguardNetworkConfig net_config(luid);

  // Extract interface addresses
  const auto &interface_config = parsed_config_->GetInterface();

  // Configure IP addresses
  logger_->info("Configuring IP addresses");
  if (!net_config.ConfigureIPAddresses(interface_config.addresses)) {
    logger_->error("Failed to configure IP addresses");
    return false;
  }

  // Extract allowed IPs from all peers
  std::vector<WIREGUARD_ALLOWED_IP> all_allowed_ips;
  const auto &peers = parsed_config_->GetPeers();
  for (const auto &peer : peers) {
    all_allowed_ips.insert(all_allowed_ips.end(), peer.allowed_ips.begin(), peer.allowed_ips.end());
  }

  // Configure routes
  logger_->info("Configuring routes");
  if (!net_config.ConfigureRoutes(all_allowed_ips)) {
    logger_->error("Failed to configure routes");
    return false;
  }

  logger_->info("Successfully configured network interface");
  return true;
}

bool WireguardAdapter::CleanupNetworking() {
  logger_->info("Cleaning up network configuration for adapter: {}", WideToUtf8(name_));

  if (!IsValid()) {
    logger_->error("Adapter is not valid for network cleanup");
    return false;
  }

  NET_LUID luid;
  if (!GetLUID(&luid)) {
    logger_->error("Failed to get adapter LUID for network cleanup");
    return false;
  }

  // Create network config helper
  WireguardNetworkConfig net_config(luid);

  // Remove IP addresses and routes
  bool success = true;

  logger_->info("Removing IP addresses");
  if (!net_config.RemoveIPAddresses()) {
    logger_->warn("Failed to remove some IP addresses");
    success = false;
  }

  logger_->info("Removing routes");
  if (!net_config.RemoveRoutes()) {
    logger_->warn("Failed to remove some routes");
    success = false;
  }

  if (success) {
    logger_->info("Successfully cleaned up network configuration");
  } else {
    logger_->warn("Network cleanup completed with some errors");
  }

  return success;
}

} // namespace wireguard_dart
