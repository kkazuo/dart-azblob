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

  static final String defaultEndpointsProtocol = 'DefaultEndpointsProtocol';
  static final String endpointSuffix = 'EndpointSuffix';
  static final String accountName = 'AccountName';

  // ignore: non_constant_identifier_names
  static final String AccountKey = 'AccountKey';

  /// Initialize with connection string.
  AzureStorage.parse(String connectionString) {
    try {
      var m = <String, String>{};
      var items = connectionString.split(';');
      for (var item in items) {
        var i = item.indexOf('=');
        var key = item.substring(0, i);
        var val = item.substring(i + 1);
        m[key] = val;
      }
      config = m;
      accountKey = base64Decode(config[AccountKey]!);
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
    var scheme = config[defaultEndpointsProtocol] ?? 'https';
    var suffix = config[endpointSuffix] ?? 'core.windows.net';
    var name = config[accountName];
    return Uri(
        scheme: scheme,
        host: '$name.blob.$suffix',
        path: path,
        queryParameters: queryParameters);
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
    var keys = items.keys.toList();
    keys.sort();
    return keys.map((i) => '\n$i:${items[i]}').join();
  }

  void sign(http.HttpClientRequest request) {
    request.headers.set('x-ms-date', formatHttpDate(DateTime.now()));
    request.headers.set('x-ms-version', '2019-12-12');
    var ce = request.headers['Content-Encoding'] ?? '';
    var cl = request.headers['Content-Language'] ?? '';
    var cz = request.contentLength <= 0 ? '' : '${request.contentLength}';
    var cm = request.headers['Content-MD5'] ?? '';
    var ct = request.headers['Content-Type'] ?? '';
    var dt = request.headers['Date'] ?? '';
    var ims = request.headers['If-Modified-Since'] ?? '';
    var imt = request.headers['If-Match'] ?? '';
    var inm = request.headers['If-None-Match'] ?? '';
    var ius = request.headers['If-Unmodified-Since'] ?? '';
    var ran = request.headers['Range'] ?? '';
    var chs = _canonicalHeaders(request.headers);
    var crs = _canonicalResources(request.uri.queryParameters);
    var name = config[accountName];
    var path = request.uri.path;
    var sig =
        '${request.method}\n$ce\n$cl\n$cz\n$cm\n$ct\n$dt\n$ims\n$imt\n$inm\n$ius\n$ran\n$chs/$name$path$crs';
    var mac = crypto.Hmac(crypto.sha256, accountKey);
    var digest = base64Encode(mac.convert(utf8.encode(sig)).bytes);
    var auth = 'SharedKey $name:$digest';
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
    var (container, rest) = _splitPathSegment(path);
    var request = await _client.openUrl(
        'GET',
        uri(path: container, queryParameters: {
          "restype": "container",
          "comp": "list",
          if (rest != null) "prefix": rest,
        }));
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
    var request = await _client.openUrl('DELETE', uri(path: path));
    sign(request);
    return request.close();
  }

  String _signedExpiry(DateTime? expiry) {
    var str = (expiry ?? DateTime.now().add(const Duration(hours: 1)))
        .toUtc()
        .toIso8601String();
    return '${str.substring(0, str.indexOf('.'))}Z';
  }

  /// Get Blob Link.
  Future<Uri> getBlobLink(String path, {DateTime? expiry}) async {
    var signedPermissions = 'r';
    var signedStart = '';
    var signedExpiry = _signedExpiry(expiry);
    var signedIdentifier = '';
    var signedVersion = '2012-02-12';
    var name = config[accountName];
    var canonicalizedResource = '/$name$path';
    var str = '$signedPermissions\n'
        '$signedStart\n'
        '$signedExpiry\n'
        '$canonicalizedResource\n'
        '$signedIdentifier\n'
        '$signedVersion';
    var mac = crypto.Hmac(crypto.sha256, accountKey);
    var sig = base64Encode(mac.convert(utf8.encode(str)).bytes);
    return uri(path: path, queryParameters: {
      'sr': 'b',
      'sp': signedPermissions,
      'se': signedExpiry,
      'sv': signedVersion,
      'spr': 'https',
      'sig': sig,
    });
  }

  /// Put Blob.
  ///
  /// `body` and `bodyBytes` are exclusive and mandatory.
  Future<void> putBlob(String path,
      {String? body,
      Uint8List? bodyBytes,
      String? contentType,
      BlobType type = BlobType.blockBlob,
      Map<String, String>? headers}) async {
    var request = await _client.openUrl('PUT', uri(path: path));
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
    var res = await request.close();
    if (res.statusCode == 201) {
      await res.drain();
      if (type == BlobType.appendBlob && (body != null || bodyBytes != null)) {
        await appendBlock(path, body: body, bodyBytes: bodyBytes);
      }
      return;
    }

    var message = (await res.transform(const Utf8Decoder()).toList()).join();
    print(message);
    throw AzureStorageException(message, res.statusCode, res.headers);
  }

  /// Append block to blob.
  Future<void> appendBlock(String path,
      {String? body, Uint8List? bodyBytes}) async {
    var request = await _client.openUrl(
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
    var res = await request.close();
    if (res.statusCode == 201) {
      await res.drain();
      return;
    }

    var message = (await res.transform(const Utf8Decoder()).toList()).join();
    throw AzureStorageException(message, res.statusCode, res.headers);
  }
}
