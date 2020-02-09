A trivial Azure Blob Storage client.

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
