#include "wireguard_dart_plugin.h"

#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <libbase64.h>

#include <algorithm>
#include <memory>
#include <sstream>

// Windows networking includes
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include "connection_status.h"
#include "key_generator.h"
#include "network_adapter_status_observer.h"
#include "spdlog/spdlog.h"
#include "tunnel.h"
#include "utils.h"
#include "wireguard.h"
#include "wireguard_adapter.h"
#include "wireguard_config_parser.h"
#include "wireguard_library.h"

// Declare the function prototype
std::string GetLastErrorAsString(DWORD error_code);

// Helper functions for Windows network configuration
bool ConfigureAdapterIPAddress(NET_LUID luid, const std::vector<WIREGUARD_ALLOWED_IP>& addresses);
bool AddRouteForAllowedIPs(NET_LUID luid, const std::vector<WIREGUARD_ALLOWED_IP>& allowed_ips);
bool RemoveAdapterIPAddresses(NET_LUID luid);
bool RemoveRoutesForAdapter(NET_LUID luid);

namespace wireguard_dart {

// static
void WireguardDartPlugin::RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar) {
  auto channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      registrar->messenger(), "wireguard_dart", &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<WireguardDartPlugin>();

  channel->SetMethodCallHandler([plugin_pointer = plugin.get()](const auto &call, auto result) {
    plugin_pointer->HandleMethodCall(call, std::move(result));
  });

  auto status_channel = std::make_unique<flutter::EventChannel<flutter::EncodableValue>>(
      registrar->messenger(), "wireguard_dart/status", &flutter::StandardMethodCodec::GetInstance());

  plugin->network_adapter_observer_ = std::make_unique<NetworkAdapterStatusObserver>();
  auto status_channel_handler = std::make_unique<flutter::StreamHandlerFunctions<>>(
      [plugin_pointer = plugin.get()](
          const flutter::EncodableValue *args,
          std::unique_ptr<flutter::EventSink<>> &&events) -> std::unique_ptr<flutter::StreamHandlerError<>> {
        return plugin_pointer->network_adapter_observer_->OnListen(args, std::move(events));
      },
      [plugin_pointer =
           plugin.get()](const flutter::EncodableValue *args) -> std::unique_ptr<flutter::StreamHandlerError<>> {
        return plugin_pointer->network_adapter_observer_->OnCancel(args);
      });

  status_channel->SetStreamHandler(std::move(status_channel_handler));

  registrar->AddPlugin(std::move(plugin));
}

WireguardDartPlugin::WireguardDartPlugin() {
  // Initialize logger
  try {
    logger_ = spdlog::get("wireguard_dart");
    if (!logger_) {
      logger_ = spdlog::default_logger();
      logger_->info("WireguardDartPlugin initialized with default logger");
    }
  } catch (const std::exception &e) {
    // Fallback to default logger if initialization fails
    logger_ = spdlog::default_logger();
    logger_->warn("Failed to initialize named logger, using default: {}", e.what());
  }
}

WireguardDartPlugin::~WireguardDartPlugin() { this->network_adapter_observer_->StopAllObserving(); }

WireguardAdapter *WireguardDartPlugin::FindAdapterByName(const std::wstring &adapter_name) {
  auto adapter_it = std::find_if(adapters_.begin(), adapters_.end(),
                                 [&adapter_name](const std::unique_ptr<WireguardAdapter> &adapter) {
                                   return adapter && adapter->GetName() == adapter_name;
                                 });

  return (adapter_it != adapters_.end()) ? adapter_it->get() : nullptr;
}

std::optional<WireguardMethod> WireguardDartPlugin::GetMethodFromString(const std::string &method_name) {
  if (method_name == "generateKeyPair")
    return WireguardMethod::GENERATE_KEY_PAIR;
  if (method_name == "checkTunnelConfiguration")
    return WireguardMethod::CHECK_TUNNEL_CONFIGURATION;
  if (method_name == "nativeInit")
    return WireguardMethod::NATIVE_INIT;
  if (method_name == "setupTunnel")
    return WireguardMethod::SETUP_TUNNEL;
  if (method_name == "connect")
    return WireguardMethod::CONNECT;
  if (method_name == "disconnect")
    return WireguardMethod::DISCONNECT;
  if (method_name == "status")
    return WireguardMethod::STATUS;
  return std::nullopt;
}

void WireguardDartPlugin::HandleMethodCall(const flutter::MethodCall<flutter::EncodableValue> &call,
                                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const auto *args = std::get_if<flutter::EncodableMap>(call.arguments());

  auto method = GetMethodFromString(call.method_name());

  if (!method.has_value()) {
    result->NotImplemented();
    return;
  }

  switch (method.value()) {
    case WireguardMethod::GENERATE_KEY_PAIR:
      HandleGenerateKeyPair(args, std::move(result));
      break;
    case WireguardMethod::CHECK_TUNNEL_CONFIGURATION:
      HandleCheckTunnelConfiguration(args, std::move(result));
      break;
    case WireguardMethod::NATIVE_INIT:
      HandleNativeInit(args, std::move(result));
      break;
    case WireguardMethod::SETUP_TUNNEL:
      HandleSetupTunnel(args, std::move(result));
      break;
    case WireguardMethod::CONNECT:
      HandleConnect(args, std::move(result));
      break;
    case WireguardMethod::DISCONNECT:
      HandleDisconnect(args, std::move(result));
      break;
    case WireguardMethod::STATUS:
      HandleStatus(args, std::move(result));
      break;
  }
}

void WireguardDartPlugin::HandleGenerateKeyPair(
    const flutter::EncodableMap *args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Generate key pair initiated");
  std::pair public_private_keypair = GenerateKeyPair();
  std::map<flutter::EncodableValue, flutter::EncodableValue> return_value;
  return_value[flutter::EncodableValue("publicKey")] = flutter::EncodableValue(public_private_keypair.first);
  return_value[flutter::EncodableValue("privateKey")] = flutter::EncodableValue(public_private_keypair.second);
  result->Success(flutter::EncodableValue(return_value));
  logger_->info("Generate key pair completed successfully");
}

void WireguardDartPlugin::HandleCheckTunnelConfiguration(
    const flutter::EncodableMap *args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Check tunnel configuration initiated");

  // Check if we have any valid adapters created
  bool has_adapter = !adapters_.empty() && adapters_.back() && adapters_.back()->IsValid();
  bool is_configured = has_adapter;

  result->Success(flutter::EncodableValue(is_configured));
  logger_->info("Check tunnel configuration completed - configured: {}, adapter: {}", is_configured, has_adapter);
}

void WireguardDartPlugin::HandleNativeInit(const flutter::EncodableMap *args,
                                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Native init initiated");

  // Initialize WireGuard library
  wg_library_ = WireguardLibrary::Create();
  if (wg_library_) {
    logger_->info("WireGuard library loaded successfully");
  } else {
    logger_->error("Failed to load WireGuard library - adapter management will "
                   "not be possible");
    result->Error("Failed to load WireGuard library");
    return;
  }

  result->Success();
  logger_->info("Native init completed successfully");
}

void WireguardDartPlugin::HandleSetupTunnel(const flutter::EncodableMap *args,
                                            std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Setup tunnel initiated");
  const auto *arg_service_name = std::get_if<std::string>(ValueOrNull(*args, "win32ServiceName"));
  if (arg_service_name == NULL) {
    logger_->error("Setup tunnel failed: win32ServiceName argument missing");
    result->Error("Argument 'win32ServiceName' is required");
    return;
  }

  std::wstring adapter_name = Utf8ToWide(*arg_service_name);

  // Check if WireGuard library is available
  if (!wg_library_ || !wg_library_->IsLoaded()) {
    logger_->error("Setup tunnel failed: WireGuard library not available");
    result->Error("WIREGUARD_LIBRARY_NOT_AVAILABLE", "WireGuard library is not loaded");
    return;
  }

  // Check if adapter already exists
  if (FindAdapterByName(adapter_name)) {
    logger_->info("Setup tunnel completed - adapter already exists: {}", *arg_service_name);
    // Ensure the observer is started with the existing adapter
    WireguardAdapter *existing_adapter = FindAdapterByName(adapter_name);
    if (existing_adapter && existing_adapter->IsValid()) {
      NET_LUID luid;
      if (existing_adapter->GetLUID(&luid)) {
        this->network_adapter_observer_->StartObserving(luid);
      }
    }
    result->Success();
    return;
  }

  // Try to open existing adapter first
  auto adapter = WireguardAdapter::Open(wg_library_, adapter_name);
  if (!adapter) {
    // If opening fails, create a new adapter
    logger_->info("Creating new WireGuard adapter: {}", *arg_service_name);
    adapter = WireguardAdapter::Create(wg_library_, adapter_name, L"WireGuard");
    if (!adapter) {
      DWORD error_code = GetLastError();
      std::string error_message = "Failed to create WireGuard adapter: " + *arg_service_name;
      if (error_code != 0) {
        error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
        error_message += " Description: " + GetLastErrorAsString(error_code);
      }
      logger_->error("Setup tunnel failed: {}", error_message);
      result->Error("ADAPTER_CREATION_FAILED", error_message);
      return;
    }
    logger_->info("WireGuard adapter created successfully: {}", *arg_service_name);
  } else {
    logger_->info("Opened existing WireGuard adapter: {}", *arg_service_name);
  }

  // Store the adapter
  NET_LUID luid;
  if (adapter->GetLUID(&luid)) {
    this->network_adapter_observer_->StartObserving(luid);
  }
  adapters_.push_back(std::move(adapter));

  result->Success();
}

void WireguardDartPlugin::HandleConnect(const flutter::EncodableMap *args,
                                        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Connect initiated");

  // Get required arguments
  const auto *arg_service_name = std::get_if<std::string>(ValueOrNull(*args, "win32ServiceName"));
  if (arg_service_name == NULL) {
    logger_->error("Connect failed: win32ServiceName argument missing");
    result->Error("Argument 'win32ServiceName' is required");
    return;
  }

  const auto *cfg = std::get_if<std::string>(ValueOrNull(*args, "cfg"));
  if (cfg == NULL) {
    logger_->error("Connect failed: cfg argument missing");
    result->Error("Argument 'cfg' is required");
    return;
  }

  // Find the adapter by name
  std::wstring adapter_name = Utf8ToWide(*arg_service_name);
  WireguardAdapter *target_adapter = FindAdapterByName(adapter_name);

  if (!target_adapter) {
    logger_->error("Connect failed: adapter not found: {}", *arg_service_name);
    result->Error("ADAPTER_NOT_FOUND", "Adapter not found. Call 'setupTunnel' first.");
    return;
  }

  if (!target_adapter->IsValid()) {
    logger_->error("Connect failed: adapter is not valid: {}", *arg_service_name);
    result->Error("ADAPTER_INVALID", "Adapter is not valid");
    return;
  }

  // Apply configuration to the adapter
  try {
    if (!target_adapter->ApplyConfiguration(*cfg)) {
      DWORD error_code = GetLastError();
      std::string error_message = "Failed to apply configuration to adapter";
      if (error_code != 0) {
        error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
        error_message += " Description: " + GetLastErrorAsString(error_code);
      }
      logger_->error("Connect failed: {}", error_message);
      result->Error("CONFIGURATION_FAILED", error_message);
      return;
    }
    
    // Parse the configuration to extract interface addresses and peer allowed IPs for routing
    WireguardConfigParser parser;
    if (!parser.Parse(*cfg)) {
      logger_->error("Connect failed: unable to parse configuration for network setup");
      result->Error("CONFIGURATION_PARSE_FAILED", "Failed to parse configuration for network setup");
      return;
    }
    
    // Configure Windows networking for the adapter
    NET_LUID luid;
    if (target_adapter->GetLUID(&luid)) {
      // Configure IP addresses from the interface section
      const auto& interface_config = parser.GetInterface();
      if (!interface_config.addresses.empty()) {
        logger_->info("Configuring IP addresses for adapter");
        if (!ConfigureAdapterIPAddress(luid, interface_config.addresses)) {
          DWORD error_code = GetLastError();
          std::string error_message = "Failed to configure IP addresses on adapter";
          if (error_code != 0) {
            error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
            error_message += " Description: " + GetLastErrorAsString(error_code);
          }
          logger_->error("Connect failed: {}", error_message);
          result->Error("IP_CONFIGURATION_FAILED", error_message);
          return;
        }
        logger_->info("Successfully configured IP addresses");
      }
      
      // Add routes for peer allowed IPs
      const auto& peers = parser.GetPeers();
      for (const auto& peer : peers) {
        if (!peer.allowed_ips.empty()) {
          logger_->info("Configuring routes for peer allowed IPs");
          if (!AddRouteForAllowedIPs(luid, peer.allowed_ips)) {
            DWORD error_code = GetLastError();
            std::string error_message = "Failed to configure routes for peer allowed IPs";
            if (error_code != 0) {
              error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
              error_message += " Description: " + GetLastErrorAsString(error_code);
            }
            logger_->warn("Connect warning: {} (continuing anyway)", error_message);
            // Don't fail the connection for routing issues, just warn
          } else {
            logger_->info("Successfully configured routes for peer allowed IPs");
          }
        }
      }
    } else {
      logger_->warn("Connect warning: unable to get adapter LUID for network configuration");
    }
  } catch (const std::exception &e) {
    DWORD error_code = GetLastError();
    std::string error_message = "Exception while applying configuration: ";
    error_message += e.what();
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Connect failed: {}", error_message);
    result->Error("CONFIGURATION_EXCEPTION", error_message);
    return;
  } catch (...) {
    DWORD error_code = GetLastError();
    std::string error_message = "Unknown error occurred while applying configuration.";
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Connect failed: {}", error_message);
    result->Error("UNKNOWN_ERROR", error_message);
    return;
  }

  // Start observing the adapter (it should already be started from setup, but
  // ensure it's running)
  NET_LUID luid;
  if (target_adapter->GetLUID(&luid)) {
    if (!this->network_adapter_observer_->IsMonitoring(luid)) {
      this->network_adapter_observer_->StartObserving(luid);
    }
  }

  result->Success();
  logger_->info("Connect completed successfully for adapter: {}", *arg_service_name);
}

void WireguardDartPlugin::HandleDisconnect(const flutter::EncodableMap *args,
                                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Disconnect initiated");

  // Get required arguments
  const auto *arg_service_name = std::get_if<std::string>(ValueOrNull(*args, "win32ServiceName"));
  if (arg_service_name == NULL) {
    logger_->error("Disconnect failed: win32ServiceName argument missing");
    result->Error("Argument 'win32ServiceName' is required");
    return;
  }

  // Find the adapter by name
  std::wstring adapter_name = Utf8ToWide(*arg_service_name);
  WireguardAdapter *target_adapter = FindAdapterByName(adapter_name);

  if (!target_adapter) {
    logger_->error("Disconnect failed: adapter not found: {}", *arg_service_name);
    result->Error("ADAPTER_NOT_FOUND", "Adapter not found");
    return;
  }

  if (!target_adapter->IsValid()) {
    logger_->error("Disconnect failed: adapter is not valid: {}", *arg_service_name);
    result->Error("ADAPTER_INVALID", "Adapter is not valid");
    return;
  }

  // Set adapter state to DOWN
  try {
    if (!target_adapter->SetState(WIREGUARD_ADAPTER_STATE_DOWN)) {
      DWORD error_code = GetLastError();
      std::string error_message = "Failed to set adapter state to DOWN";
      if (error_code != 0) {
        error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
        error_message += " Description: " + GetLastErrorAsString(error_code);
      }
      logger_->error("Disconnect failed: {}", error_message);
      result->Error("ADAPTER_STATE_FAILED", error_message);
      return;
    }
  } catch (const std::exception &e) {
    DWORD error_code = GetLastError();
    std::string error_message = "Exception while setting adapter state: ";
    error_message += e.what();
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Disconnect failed: {}", error_message);
    result->Error("ADAPTER_EXCEPTION", error_message);
    return;
  } catch (...) {
    DWORD error_code = GetLastError();
    std::string error_message = "Unknown error occurred while setting adapter state.";
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Disconnect failed: {}", error_message);
    result->Error("UNKNOWN_ERROR", error_message);
    return;
  }

  // Stop observing this specific adapter
  NET_LUID luid;
  if (target_adapter->GetLUID(&luid)) {
    // Clean up network configuration
    logger_->info("Cleaning up network configuration for adapter");
    
    // Remove IP addresses (this will also clean up associated routes automatically)
    if (!RemoveAdapterIPAddresses(luid)) {
      DWORD error_code = GetLastError();
      std::string error_message = "Warning: Failed to remove IP addresses from adapter";
      if (error_code != 0) {
        error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
        error_message += " Description: " + GetLastErrorAsString(error_code);
      }
      logger_->warn("Disconnect warning: {} (continuing anyway)", error_message);
    } else {
      logger_->info("Successfully cleaned up IP addresses");
    }
    
    // Remove any remaining routes associated with this adapter
    if (!RemoveRoutesForAdapter(luid)) {
      DWORD error_code = GetLastError();
      std::string error_message = "Warning: Failed to remove routes for adapter";  
      if (error_code != 0) {
        error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
        error_message += " Description: " + GetLastErrorAsString(error_code);
      }
      logger_->warn("Disconnect warning: {} (continuing anyway)", error_message);
    } else {
      logger_->info("Successfully cleaned up routes");
    }
    
    this->network_adapter_observer_->StopObserving(luid);
  }

  result->Success();
  logger_->info("Disconnect completed successfully for adapter: {}", *arg_service_name);
}

void WireguardDartPlugin::HandleStatus(const flutter::EncodableMap *args,
                                       std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Status check initiated");

  // Get required arguments
  const auto *arg_service_name = std::get_if<std::string>(ValueOrNull(*args, "win32ServiceName"));
  if (arg_service_name == NULL) {
    logger_->error("Status check failed: win32ServiceName argument missing");
    result->Error("Argument 'win32ServiceName' is required");
    return;
  }

  // Find the adapter by name
  std::wstring adapter_name = Utf8ToWide(*arg_service_name);
  WireguardAdapter *target_adapter = FindAdapterByName(adapter_name);

  if (!target_adapter) {
    logger_->info("Status check completed - adapter not found, returning disconnected");
    result->Success(ConnectionStatusToString(ConnectionStatus::disconnected));
    return;
  }

  if (!target_adapter->IsValid()) {
    logger_->info("Status check completed - adapter invalid, returning disconnected");
    result->Success(ConnectionStatusToString(ConnectionStatus::disconnected));
    return;
  }

  try {
    WIREGUARD_ADAPTER_STATE state = target_adapter->GetState();
    ConnectionStatus status =
        (state == WIREGUARD_ADAPTER_STATE_UP) ? ConnectionStatus::connected : ConnectionStatus::disconnected;

    result->Success(ConnectionStatusToString(status));
    logger_->info("Status check completed - adapter: {}, status: {}", *arg_service_name,
                  ConnectionStatusToString(status));
  } catch (std::exception &e) {
    logger_->error("Status check failed: {}", e.what());
    result->Error(std::string(e.what()));
  }
}
} // namespace wireguard_dart

std::string GetLastErrorAsString(DWORD error_code) {
  if (error_code == 0) {
    return "No error.";
  }

  LPSTR message_buffer = nullptr;
  size_t size =
      FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                     error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&message_buffer, 0, NULL);

  std::string message;
  if (size != 0 && message_buffer != nullptr) {
    message.assign(message_buffer, size);
    LocalFree(message_buffer);
  } else {
    message = "Unknown error code: " + std::to_string(error_code);
  }
  return message;
}

// Helper function to configure IP addresses on the adapter
bool ConfigureAdapterIPAddress(NET_LUID luid, const std::vector<WIREGUARD_ALLOWED_IP>& addresses) {
  for (const auto& addr : addresses) {
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    
    row.InterfaceLuid = luid;
    row.DadState = IpDadStatePreferred;
    row.ValidLifetime = 0xffffffff; // INFINITE
    row.PreferredLifetime = 0xffffffff; // INFINITE
    row.OnLinkPrefixLength = addr.Cidr;
    
    if (addr.AddressFamily == AF_INET) {
      row.Address.Ipv4.sin_family = AF_INET;
      row.Address.Ipv4.sin_addr = addr.Address.V4;
    } else if (addr.AddressFamily == AF_INET6) {
      row.Address.Ipv6.sin6_family = AF_INET6;
      row.Address.Ipv6.sin6_addr = addr.Address.V6;
    } else {
      continue; // Skip unsupported address families
    }
    
    DWORD result = CreateUnicastIpAddressEntry(&row);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
      SetLastError(result);
      return false;
    }
  }
  return true;
}

// Helper function to add routes for allowed IPs
bool AddRouteForAllowedIPs(NET_LUID luid, const std::vector<WIREGUARD_ALLOWED_IP>& allowed_ips) {
  for (const auto& allowed_ip : allowed_ips) {
    MIB_IPFORWARD_ROW2 route;
    InitializeIpForwardEntry(&route);
    
    route.InterfaceLuid = luid;
    route.Protocol = MIB_IPPROTO_LOCAL;
    route.Metric = 0; // Use default metric
    route.Age = 0;
    route.ValidLifetime = 0xffffffff; // INFINITE
    route.PreferredLifetime = 0xffffffff; // INFINITE
    
    if (allowed_ip.AddressFamily == AF_INET) {
      route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
      route.DestinationPrefix.Prefix.Ipv4.sin_addr = allowed_ip.Address.V4;
      route.DestinationPrefix.PrefixLength = allowed_ip.Cidr;
      
      // Set next hop to unspecified (0.0.0.0) for direct routing
      route.NextHop.Ipv4.sin_family = AF_INET;
      route.NextHop.Ipv4.sin_addr.s_addr = 0;
    } else if (allowed_ip.AddressFamily == AF_INET6) {
      route.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
      route.DestinationPrefix.Prefix.Ipv6.sin6_addr = allowed_ip.Address.V6;
      route.DestinationPrefix.PrefixLength = allowed_ip.Cidr;
      
      // Set next hop to unspecified (::) for direct routing  
      route.NextHop.Ipv6.sin6_family = AF_INET6;
      memset(&route.NextHop.Ipv6.sin6_addr, 0, sizeof(route.NextHop.Ipv6.sin6_addr));
    } else {
      continue; // Skip unsupported address families
    }
    
    DWORD result = CreateIpForwardEntry2(&route);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
      SetLastError(result);
      return false;
    }
  }
  return true;
}

// Helper function to remove IP addresses from adapter
bool RemoveAdapterIPAddresses(NET_LUID luid) {
  PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
  
  DWORD result = GetUnicastIpAddressTable(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    SetLastError(result);
    return false;
  }
  
  bool success = true;
  for (ULONG i = 0; i < table->NumEntries; i++) {
    if (table->Table[i].InterfaceLuid.Value == luid.Value) {
      DWORD delete_result = DeleteUnicastIpAddressEntry(&table->Table[i]);
      if (delete_result != NO_ERROR && delete_result != ERROR_NOT_FOUND) {
        success = false;
        SetLastError(delete_result);
      }
    }
  }
  
  FreeMibTable(table);
  return success;
}

// Helper function to remove routes for adapter  
bool RemoveRoutesForAdapter(NET_LUID luid) {
  PMIB_IPFORWARD_TABLE2 table = nullptr;
  
  DWORD result = GetIpForwardTable2(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    SetLastError(result);
    return false;
  }
  
  bool success = true;
  for (ULONG i = 0; i < table->NumEntries; i++) {
    if (table->Table[i].InterfaceLuid.Value == luid.Value) {
      DWORD delete_result = DeleteIpForwardEntry2(&table->Table[i]);
      if (delete_result != NO_ERROR && delete_result != ERROR_NOT_FOUND) {
        success = false;
        SetLastError(delete_result);
      }
    }
  }
  
  FreeMibTable(table);
  return success;
}
