import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:wireguard_dart/connection_status.dart';
import 'package:wireguard_dart/key_pair.dart';
import 'package:wireguard_dart/tunnel_statistics.dart';

import 'wireguard_dart_platform_interface.dart';

enum WireguardMethodChannelMethod {
  generateKeyPair('generateKeyPair'),
  nativeInit('nativeInit'),
  setupTunnel('setupTunnel'),
  connect('connect'),
  disconnect('disconnect'),
  status('status'),
  checkTunnelConfiguration('checkTunnelConfiguration'),
  removeTunnelConfiguration('removeTunnelConfiguration'),
  tunnelStatistics('tunnelStatistics');

  const WireguardMethodChannelMethod(this.value);
  final String value;
}

class MethodChannelWireguardDart extends WireguardDartPlatform {
  @visibleForTesting
  final methodChannel = const MethodChannel('wireguard_dart');
  final statusChannel = const EventChannel('wireguard_dart/status');

  @override
  Future<KeyPair> generateKeyPair() async {
    final result = await methodChannel.invokeMapMethod<String, String>(WireguardMethodChannelMethod.generateKeyPair.value) ?? <String, String>{};
    if (!result.containsKey('publicKey') || !result.containsKey('privateKey')) {
      throw StateError('Could not generate keypair');
    }
    return KeyPair(result['publicKey']!, result['privateKey']!);
  }

  @override
  Future<void> nativeInit() async {
    await methodChannel.invokeMethod<void>(WireguardMethodChannelMethod.nativeInit.value);
  }

  @override
  Future<void> setupTunnel({required String bundleId, required String tunnelName, String? win32ServiceName}) async {
    final args = {
      'bundleId': bundleId,
      'tunnelName': tunnelName,
      if (win32ServiceName != null) 'win32ServiceName': win32ServiceName,
    };
    await methodChannel.invokeMethod<void>(WireguardMethodChannelMethod.setupTunnel.value, args);
  }

  @override
  Future<void> connect({required String cfg}) async {
    await methodChannel.invokeMethod<void>(WireguardMethodChannelMethod.connect.value, {'cfg': cfg});
  }

  @override
  Future<void> disconnect() async {
    await methodChannel.invokeMethod<void>(WireguardMethodChannelMethod.disconnect.value);
  }

  @override
  Future<ConnectionStatus> status() async {
    final result = await methodChannel.invokeMethod<String>(WireguardMethodChannelMethod.status.value);
    return ConnectionStatus.fromString(result ?? "");
  }

  @override
  Stream<ConnectionStatus> statusStream() {
    return statusChannel.receiveBroadcastStream().distinct().map((val) => ConnectionStatus.fromString(val));
  }

  @override
  Future<bool> checkTunnelConfiguration({
    required String bundleId,
    required String tunnelName,
  }) async {
    final result = await methodChannel.invokeMethod<bool>(WireguardMethodChannelMethod.checkTunnelConfiguration.value, {
      'bundleId': bundleId,
      'tunnelName': tunnelName,
    });
    return result as bool;
  }

  @override
  Future<void> removeTunnelConfiguration({required String bundleId, required String tunnelName}) async {
    await methodChannel.invokeMethod<void>(WireguardMethodChannelMethod.removeTunnelConfiguration.value, {
      'bundleId': bundleId,
      'tunnelName': tunnelName,
    });
  }

  @override
  Future<TunnelStatistics?> getTunnelStatistics() async {
    try {
      final result = await methodChannel.invokeMethod(WireguardMethodChannelMethod.tunnelStatistics.value);
      final stats = TunnelStatistics.fromJson(jsonDecode(result));
      return stats;
    } catch (e) {
      throw Exception(e);
    }
  }
}
