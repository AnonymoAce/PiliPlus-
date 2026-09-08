// x-bili-ticket 获取与缓存（bilibili.api.ticket.v1.Ticket/GetTicket），供 gRPC 业务请求头附带，修复登录态下评论接口被静默挂起
import 'dart:convert';
import 'dart:typed_data';

import 'package:PiliPlus/grpc/bilibili/metadata/device.pb.dart';
import 'package:PiliPlus/grpc/grpc_req.dart';
import 'package:PiliPlus/http/constants.dart';
import 'package:PiliPlus/http/init.dart';
import 'package:PiliPlus/utils/accounts.dart';
import 'package:PiliPlus/utils/login_utils.dart';
import 'package:PiliPlus/utils/storage_pref.dart';
import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:fixnum/fixnum.dart';

abstract final class BiliTicket {
  static const _keyId = 'ec01';
  static const _hmacKey = 'Ezlc3tgtl';
  static const url =
      '${HttpString.appBaseUrl}/bilibili.api.ticket.v1.Ticket/GetTicket';

  static String? _ticket;
  static String? _ticketMid;
  static int _expireAtMs = 0;
  static int _retryAfterMs = 0;
  static Future<String>? _pending;

  static Future<String> get() async {
    final account = Accounts.main;
    final mid = account.isLogin ? account.mid.toString() : '0';
    final now = DateTime.now().millisecondsSinceEpoch;
    if (_ticket != null && _ticketMid == mid && now < _expireAtMs) {
      return _ticket!;
    }
    if (_ticket == null) {
      final String? cached = Pref.biliTicket;
      final int? cachedExpire = Pref.biliTicketExpire;
      final String? cachedMid = Pref.biliTicketMid;
      if (cached != null &&
          cachedExpire != null &&
          cachedMid != null &&
          cachedMid == mid &&
          now < cachedExpire) {
        _ticket = cached;
        _ticketMid = cachedMid;
        _expireAtMs = cachedExpire;
        return cached;
      }
    }
    if (now < _retryAfterMs) {
      return _ticketMid == mid ? _ticket ?? '' : '';
    }
    return _pending ??= _fetch(mid).whenComplete(() => _pending = null);
  }

  static Future<String> _fetch(String mid) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    try {
      final fpLocal = Pref.biliFpLocal;
      final fts = Pref.biliTicketFts;
      // Device 参数集必须与 GrpcHeaders._base 完全一致，保证 device-bin 字节一致
      final deviceBin = Device(
        appId: 5,
        build: 2001100,
        buvid: LoginUtils.buvid,
        mobiApp: 'android_hd',
        platform: 'android',
        channel: 'master',
        brand: 'android',
        model: 'android',
        osver: '15',
        versionName: '2.0.1',
        fpLocal: fpLocal,
        fpRemote: fpLocal,
        fp: fpLocal,
        fts: Int64(fts),
      ).writeToBuffer();
      final fpBin = _encodeDeviceInfo(fts, mid, fpLocal);
      final context = <String, Uint8List>{
        'x-exbadbasket': Uint8List(0),
        'x-fingerprint': fpBin,
      };
      final keys = context.keys.toList()..sort();

      final signer = BytesBuilder()..add(deviceBin);
      for (final key in keys) {
        signer..add(utf8.encode(key))..add(context[key]!);
      }
      final sign = Hmac(sha256, utf8.encode(_hmacKey))
          .convert(signer.toBytes())
          .bytes;

      final msg = BytesBuilder();
      for (final key in keys) {
        final entry = BytesBuilder();
        _writeBytesField(entry, 1, utf8.encode(key));
        _writeBytesField(entry, 2, context[key]!);
        _writeBytesField(msg, 1, entry.toBytes());
      }
      _writeBytesField(msg, 2, utf8.encode(_keyId));
      _writeBytesField(msg, 3, sign);

      final res = await Request().post<Uint8List>(
        url,
        data: GrpcReq.compressProtobuf(msg.toBytes()),
        options: Options(
          contentType: 'application/grpc',
          responseType: ResponseType.bytes,
        ),
      );
      if (res.data case final Uint8List data when data.length > 5) {
        final (ticket, ttl) = _parseTicket(
          GrpcReq.decompressProtobuf(data),
        );
        if (ticket.isNotEmpty) {
          _ticket = ticket;
          _ticketMid = mid;
          _expireAtMs = now + ((ttl > 1200 ? ttl : 18000) - 600) * 1000;
          Pref.saveBiliTicket(ticket, _expireAtMs, mid);
          return ticket;
        }
      }
    } catch (_) {
      // fail-open
    }
    _retryAfterMs = now + 60000;
    return _ticket ?? '';
  }

  // DeviceInfo(x-fingerprint) 最小集，proto3 跳过默认值
  static Uint8List _encodeDeviceInfo(int fts, String mid, String fpLocal) {
    final b = BytesBuilder();
    _writeStringField(b, 1, '0.2.4'); // sdkver
    _writeStringField(b, 2, '5'); // app_id
    _writeStringField(b, 3, '2.0.1'); // app_version
    _writeStringField(b, 4, '2001100'); // app_version_code
    _writeStringField(b, 5, mid); // mid
    _writeStringField(b, 6, 'master'); // chid
    _writeVarintField(b, 7, fts); // fts
    _writeStringField(b, 8, fpLocal); // buvid_local
    _writeStringField(b, 13, '15'); // osver
    _writeStringField(b, 16, 'android'); // model
    _writeStringField(b, 17, 'android'); // brand
    _writeStringField(b, 22, '000'); // emu
    _writeStringField(b, 35, 'android'); // os
    return b.toBytes();
  }

  static (String, int) _parseTicket(Uint8List buf) {
    var ticket = '';
    var ttl = 0;
    var i = 0;
    final len = buf.length;

    int readVarint() {
      var v = 0;
      var shift = 0;
      while (true) {
        final byte = buf[i++];
        v |= (byte & 0x7F) << shift;
        if (byte & 0x80 == 0) {
          return v;
        }
        shift += 7;
      }
    }

    while (i < len) {
      final tag = readVarint();
      final field = tag >> 3;
      switch (tag & 7) {
        case 0:
          final v = readVarint();
          if (field == 3) {
            ttl = v;
          }
        case 2:
          final l = readVarint();
          final end = i + l;
          if (end > len) {
            throw const FormatException('ticket: bad field length');
          }
          if (field == 1) {
            ticket = utf8.decode(buf.sublist(i, end), allowMalformed: true);
          }
          i = end;
        case 5:
          i += 4;
        case 1:
          i += 8;
        default:
          return (ticket, ttl);
      }
    }
    return (ticket, ttl);
  }

  static void _writeVarint(BytesBuilder b, int v) {
    while (v >= 0x80) {
      b.addByte((v & 0x7F) | 0x80);
      v >>>= 7;
    }
    b.addByte(v);
  }

  static void _writeVarintField(BytesBuilder b, int field, int v) {
    if (v == 0) {
      return; // proto3 默认值跳过
    }
    _writeVarint(b, field << 3);
    _writeVarint(b, v);
  }

  static void _writeBytesField(BytesBuilder b, int field, List<int> bytes) {
    _writeVarint(b, (field << 3) | 2);
    _writeVarint(b, bytes.length);
    b.add(bytes);
  }

  static void _writeStringField(BytesBuilder b, int field, String v) {
    if (v.isEmpty) {
      return; // proto3 默认值跳过
    }
    _writeBytesField(b, field, utf8.encode(v));
  }
}
