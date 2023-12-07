import 'dart:convert';
import 'package:azblob/azblob.dart';

main() async {
  var storage = AzureStorage.parse('your connection string');

  await storage.putBlob(
    '/example/yourfile.txt',
    body: 'Hello, world.',
    contentType: 'text/x-hello',
  );

  var response = await storage.getBlob('/example/yourfile.txt');
  print(response.headers.contentType);
  var body = (await response.transform(const Utf8Decoder()).toList()).join();
  print(body);

  await storage.deleteBlob('/example/yourfile.txt');

  storage.close();
}
