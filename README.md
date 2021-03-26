A trivial Azure Blob Storage client.

![workflow](https://github.com/kkazuo/dart-azblob/actions/workflows/dart.yml/badge.svg)

## Usage

A simple usage example:

```dart
import 'package:azblob/azblob.dart';

main() async {
  var storage = AzureStorage.parse('your connection string');
  await storage.putBlob('/yourcontainer/yourfile.txt',
    body: 'Hello, world.');
}
```

## License

ISC
