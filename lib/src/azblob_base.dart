import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:http_parser/http_parser.dart';
import 'package:universal_io/io.dart' as http;

/// Blob type
enum BlobType {
  blockBlob('BlockBlob'),
  appendBlob('AppendBlob'),
  ;

  const BlobType(this.displayName);

  final String displayName;
}

/// Azure Storage Exception
class AzureStorageException implements Exception {
  final String message;
  final int statusCode;
  final http.HttpHeaders headers;

  AzureStorageException(this.message, this.statusCode, this.headers);
}

/// Azure Storage Client
class AzureStorage {
  late Map<String, String> config;
  late Uint8List accountKey;

  final _client = http.newUniversalHttpClient();

  static const String defaultEndpointsProtocol = 'DefaultEndpointsProtocol';
  static const String endpointSuffix = 'EndpointSuffix';
  static const String accountName = 'AccountName';

  // ignore: non_constant_identifier_names
  static const String accountKey_ = 'AccountKey';

  /// Initialize with connection string.
  AzureStorage.parse(String connectionString) {
    try {
      final m = <String, String>{};
      final items = connectionString.split(';');
      for (final item in items) {
        final i = item.indexOf('=');
        final key = item.substring(0, i);
        final val = item.substring(i + 1);
        m[key] = val;
      }
      config = m;
      accountKey = base64Decode(config[accountKey_]!);
    } catch (e) {
      throw Exception('Parse error.');
    }
  }

  /// Close internal http client.
  void close({bool force = false}) {
    _client.close(force: force);
  }

  @override
  String toString() {
    return config.toString();
  }

  Uri uri({String path = '/', Map<String, String>? queryParameters}) {
    final scheme = config[defaultEndpointsProtocol] ?? 'https';
    final suffix = config[endpointSuffix] ?? 'core.windows.net';
    final name = config[accountName];
    return Uri(
      scheme: scheme,
      host: '$name.blob.$suffix',
      path: path,
      queryParameters: queryParameters,
    );
  }

  String _canonicalHeaders(http.HttpHeaders headers) {
    final lines = [];
    headers.forEach((name, values) {
      if (!name.startsWith('x-ms-')) return;
      lines.add('$name:${values.join()}\n');
    });
    lines.sort();
    return lines.join();
  }

  String _canonicalResources(Map<String, String> items) {
    if (items.isEmpty) {
      return '';
    }
    final keys = items.keys.toList();
    keys.sort();
    return keys.map((i) => '\n$i:${items[i]}').join();
  }

  void sign(http.HttpClientRequest request) {
    request.headers.set('x-ms-date', formatHttpDate(DateTime.now()));
    request.headers.set('x-ms-version', '2019-12-12');
    final ce = request.headers.value('Content-Encoding') ?? '';
    final cl = request.headers.value('Content-Language') ?? '';
    final cz = request.contentLength <= 0 ? '' : '${request.contentLength}';
    final cm = request.headers.value('Content-MD5') ?? '';
    final ct = request.headers.value('Content-Type') ?? '';
    final dt = request.headers.value('Date') ?? '';
    final ims = request.headers.value('If-Modified-Since') ?? '';
    final imt = request.headers.value('If-Match') ?? '';
    final inm = request.headers.value('If-None-Match') ?? '';
    final ius = request.headers.value('If-Unmodified-Since') ?? '';
    final ran = request.headers.value('Range') ?? '';
    final chs = _canonicalHeaders(request.headers);
    final crs = _canonicalResources(request.uri.queryParameters);
    final name = config[accountName];
    final path = request.uri.path;
    final sig =
        '${request.method}\n$ce\n$cl\n$cz\n$cm\n$ct\n$dt\n$ims\n$imt\n$inm\n$ius\n$ran\n$chs/$name$path$crs';
    final mac = crypto.Hmac(crypto.sha256, accountKey);
    final digest = base64Encode(mac.convert(utf8.encode(sig)).bytes);
    final auth = 'SharedKey $name:$digest';
    request.headers.set('Authorization', auth);
    // print('sig=\n$sig\n');
  }

  (String, String?) _splitPathSegment(String path) {
    final p = path.startsWith('/') ? path.substring(1) : path;
    final i = p.indexOf('/');
    if (i < 0 || p.length < i + 2) return (p, null);
    return (p.substring(0, i), p.substring(i + 1));
  }

  /// List Blobs. (Raw API)
  ///
  /// You cat use `(await response.transform(Utf8Decoder()).toList()).join();` to get blob listing as XML format.
  Future<http.HttpClientResponse> listBlobsRaw(String path) async {
    final (container, rest) = _splitPathSegment(path);
    final request = await _client.openUrl(
      'GET',
      uri(
        path: container,
        queryParameters: {
          "restype": "container",
          "comp": "list",
          if (rest != null) "prefix": rest,
        },
      ),
    );
    sign(request);
    return request.close();
  }

  /// Get Blob.
  Future<http.HttpClientResponse> getBlob(String path) async {
    final request = await _client.openUrl('GET', uri(path: path));
    sign(request);
    return request.close();
  }

  /// Delete Blob
  Future<http.HttpClientResponse> deleteBlob(String path) async {
    final request = await _client.openUrl('DELETE', uri(path: path));
    sign(request);
    return request.close();
  }

  String _signedExpiry(DateTime? expiry) {
    final str = (expiry ?? DateTime.now().add(const Duration(hours: 1)))
        .toUtc()
        .toIso8601String();
    return '${str.substring(0, str.indexOf('.'))}Z';
  }

  /// Get Blob Link.
  Future<Uri> getBlobLink(String path, {DateTime? expiry}) async {
    const signedPermissions = 'r';
    const signedStart = '';
    final signedExpiry = _signedExpiry(expiry);
    const signedIdentifier = '';
    const signedVersion = '2012-02-12';
    final name = config[accountName];
    final canonicalizedResource = '/$name$path';
    final str = '$signedPermissions\n'
        '$signedStart\n'
        '$signedExpiry\n'
        '$canonicalizedResource\n'
        '$signedIdentifier\n'
        '$signedVersion';
    final mac = crypto.Hmac(crypto.sha256, accountKey);
    final sig = base64Encode(mac.convert(utf8.encode(str)).bytes);
    return uri(
      path: path,
      queryParameters: {
        'sr': 'b',
        'sp': signedPermissions,
        'se': signedExpiry,
        'sv': signedVersion,
        'spr': 'https',
        'sig': sig,
      },
    );
  }

  /// Put Blob.
  ///
  /// `body` and `bodyBytes` are exclusive and mandatory.
  Future<void> putBlob(
    String path, {
    String? body,
    Uint8List? bodyBytes,
    String? contentType,
    BlobType type = BlobType.blockBlob,
    Map<String, String>? headers,
  }) async {
    final request = await _client.openUrl('PUT', uri(path: path));
    request.headers.set('x-ms-blob-type', type.displayName);
    if (headers != null) {
      headers.forEach((key, value) {
        request.headers.set('x-ms-meta-$key', value);
      });
    }
    if (contentType != null) {
      request.headers.contentType = ContentType.parse(contentType);
    }
    if (type == BlobType.blockBlob) {
      if (bodyBytes != null) {
        request.headers.contentLength = bodyBytes.length;
        sign(request);
        request.add(bodyBytes);
      } else if (body != null) {
        final bytes = utf8.encode(body);
        request.headers.contentLength = bytes.length;
        sign(request);
        request.add(bytes);
      } else {
        sign(request);
      }
    } else {
      sign(request);
    }
    final res = await request.close();
    if (res.statusCode == 201) {
      await res.drain();
      if (type == BlobType.appendBlob && (body != null || bodyBytes != null)) {
        await appendBlock(path, body: body, bodyBytes: bodyBytes);
      }
      return;
    }

    final message = (await res.transform(const Utf8Decoder()).toList()).join();
    throw AzureStorageException(message, res.statusCode, res.headers);
  }

  /// Append block to blob.
  Future<void> appendBlock(
    String path, {
    String? body,
    Uint8List? bodyBytes,
  }) async {
    final request = await _client.openUrl(
      'PUT',
      uri(path: path, queryParameters: {'comp': 'appendblock'}),
    );
    if (bodyBytes != null) {
      request.headers.contentLength = bodyBytes.length;
      sign(request);
      request.add(bodyBytes);
    } else if (body != null) {
      final bytes = utf8.encode(body);
      request.headers.contentLength = bytes.length;
      sign(request);
      request.add(bytes);
    }
    final res = await request.close();
    if (res.statusCode == 201) {
      await res.drain();
      return;
    }

    final message = (await res.transform(const Utf8Decoder()).toList()).join();
    throw AzureStorageException(message, res.statusCode, res.headers);
  }
}
