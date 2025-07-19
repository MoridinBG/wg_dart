#include "wireguard_dart_plugin.h"

// This must be included before many other Windows headers.
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <libbase64.h>
#include <windows.h>

#include <algorithm>
#include <memory>
#include <sstream>

#include "config_writer.h"
#include "connection_status.h"
#include "connection_status_observer.h"
#include "key_generator.h"
#include "service_control.h"
#include "spdlog/spdlog.h"
#include "tunnel.h"
#include "utils.h"
#include "wireguard.h"
#include "wireguard_adapter.h"
#include "wireguard_config_parser.h"
#include "wireguard_library.h"

// Declare the function prototype
std::string GetLastErrorAsString(DWORD error_code);

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

  plugin->connection_status_observer_ = std::make_unique<ConnectionStatusObserver>();
  auto status_channel_handler = std::make_unique<flutter::StreamHandlerFunctions<>>(
      [plugin_pointer = plugin.get()](
          const flutter::EncodableValue *args,
          std::unique_ptr<flutter::EventSink<>> &&events) -> std::unique_ptr<flutter::StreamHandlerError<>> {
        return plugin_pointer->connection_status_observer_->OnListen(args, std::move(events));
      },
      [plugin_pointer =
           plugin.get()](const flutter::EncodableValue *arguments) -> std::unique_ptr<flutter::StreamHandlerError<>> {
        return plugin_pointer->connection_status_observer_->OnCancel(arguments);
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

WireguardDartPlugin::~WireguardDartPlugin() { this->connection_status_observer_.get()->StopObserving(); }

WireguardAdapter *WireguardDartPlugin::FindAdapterByName(const std::wstring &adapter_name) {
  auto adapter_it = std::find_if(adapters_.begin(), adapters_.end(),
                                 [&adapter_name](const std::unique_ptr<WireguardAdapter> &adapter) {
                                   return adapter && adapter->GetName() == adapter_name;
                                 });

  return (adapter_it != adapters_.end()) ? adapter_it->get() : nullptr;
}

std::optional<WireguardMethod> WireguardDartPlugin::GetMethodFromString(const std::string &method_name) {
  if (method_name == "generateKeyPair") return WireguardMethod::GENERATE_KEY_PAIR;
  if (method_name == "checkTunnelConfiguration") return WireguardMethod::CHECK_TUNNEL_CONFIGURATION;
  if (method_name == "nativeInit") return WireguardMethod::NATIVE_INIT;
  if (method_name == "setupTunnel") return WireguardMethod::SETUP_TUNNEL;
  if (method_name == "connect") return WireguardMethod::CONNECT;
  if (method_name == "disconnect") return WireguardMethod::DISCONNECT;
  if (method_name == "status") return WireguardMethod::STATUS;
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

  // Check if we have any adapters created or if the service exists
  bool has_adapter = !adapters_.empty() && adapters_.back() && adapters_.back()->IsValid();
  bool has_service = this->tunnel_service_.get() != nullptr;
  bool is_configured = has_adapter || has_service;

  result->Success(flutter::EncodableValue(is_configured));
  logger_->info("Check tunnel configuration completed - configured: {}, adapter: {}, service: {}", is_configured,
                has_adapter, has_service);
}

void WireguardDartPlugin::HandleNativeInit(const flutter::EncodableMap *args,
                                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Native init initiated");

  // Initialize WireGuard library
  wg_library_ = WireguardLibrary::Create();
  if (wg_library_) {
    logger_->info("WireGuard library loaded successfully");
  } else {
    logger_->error("Failed to load WireGuard library - adapter management will not be possible");
    result->Error("Failed to load WireGuard library");
    return;
  }

  // Disable packet forwarding that conflicts with WireGuard
  ServiceControl remoteAccessService = ServiceControl(L"RemoteAccess");
  try {
    remoteAccessService.Stop();
  } catch (std::exception &e) {
    logger_->error("Failed to stop RemoteAccess service: {}", e.what());
    result->Error(std::string("Could not stop packet forwarding: ").append(e.what()));
    return;
  }
  try {
    remoteAccessService.Disable();
  } catch (std::exception &e) {
    logger_->error("Failed to disable RemoteAccess service: {}", e.what());
    result->Error(std::string("Could not disable packet forwarding: ").append(e.what()));
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
    // Ensure the observer is started
    this->connection_status_observer_.get()->StartObserving(adapter_name);
    result->Success();
    return;
  }

  // Try to open existing adapter first
  auto adapter = WireguardAdapter::Open(wg_library_, adapter_name);
  if (!adapter) {
    // If opening fails, create a new adapter
    logger_->info("Creating new WireGuard adapter: {}", *arg_service_name);
    adapter = WireguardAdapter::Create(wg_library_, adapter_name);
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

  // Start observing the adapter
  this->connection_status_observer_.get()->StartObserving(adapter_name);

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

  // Stop observing
  this->connection_status_observer_.get()->StopObserving();

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
}  // namespace wireguard_dart

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
