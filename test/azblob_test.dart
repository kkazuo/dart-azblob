import 'dart:io' as dart_io;
import 'package:http_parser/http_parser.dart' as http_parser;
import 'package:test/test.dart';

void main() {
  test('Http Date format', () {
    final date = DateTime.now();
    final dartIoString = dart_io.HttpDate.format(date);
    final httpParserString = http_parser.formatHttpDate(date);
    expect(dartIoString, httpParserString);
  });
}
