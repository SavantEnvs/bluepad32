# ds3-short-report-oob-read.bin

`uni_hid_parser_ds3_parse_input_report()` (`src/components/bluepad32/parser/uni_hid_parser_ds3.c`) only
rejects reports shorter than 30 bytes, then casts the buffer to `ds3_input_report_t` and reads fields past
byte 30 (`r->battery_status` and later). A 30..31 byte input report from a PS3-class device is a heap
over-read of one byte (ASan: heap-buffer-overflow READ of size 1, 0 bytes after the 31-byte region).

Impact: out-of-bounds read of attacker-controlled-length data from a paired Bluetooth device.
Fix: require `len >= sizeof(ds3_input_report_t)` (the fields actually dereferenced) instead of `30`.

Reproduce: `docker run <image> /mayhem/fuzz_hid_report-standalone mayhem/fuzz_hid_report/known-findings/ds3-short-report-oob-read.bin`
