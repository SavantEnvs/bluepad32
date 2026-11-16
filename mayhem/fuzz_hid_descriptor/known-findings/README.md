# btstack-hid-usage-iterator-assert.bin

A remote device's HID report descriptor reaches BTstack's `btstack_hid_usage_iterator_handle_global_item()`
(`external/btstack/src/btstack_hid_parser.c`, pinned submodule commit) through
`uni_hid_device_set_hid_descriptor()` / `uni_hid_parse_input_report()`. A descriptor containing an
unsupported global item (here `c4 00 c4`) hits `assert(0)` and aborts the process.

Impact: a malicious Bluetooth HID device can crash the host (remote DoS) during pairing/reports.
Fix: ignore unknown global items in BTstack (or validate the descriptor in bluepad32 before parsing).

Reproduce: `docker run <image> /mayhem/fuzz_hid_descriptor-standalone mayhem/fuzz_hid_descriptor/known-findings/btstack-hid-usage-iterator-assert.bin`

# btstack-hid-item-value-shift-ub.bin

`btstack_hid_descriptor_parse_item()` (`btstack_hid_parser.c:151`) builds a 32-bit item value with
`latest_byte << (8*i)`. `latest_byte` is promoted to `int`, so a 4-byte item whose last byte is >= 0x80
(here the Global item `17 00 00 00 80`) shifts a set bit into the sign bit: UBSan reports
`left shift of 128 by 24 places cannot be represented in type 'int'`. Reached from a remote device's
descriptor through `uni_hid_device_set_hid_descriptor()`.

Impact: signed-overflow UB on attacker-controlled descriptor bytes; with halting UBSan the process aborts.
Fix: cast to `uint32_t` before shifting.

# btstack-hid-usage-page-shift-ub.bin

`btstack_usage_iterator_hid_find_next_usage()` (`btstack_hid_parser.c:287`) computes
`usage_page << 16u` with a signed `int` `usage_page`. A Usage Page of 0x8000 or more (here `06 00 80`)
followed by a Local item overflows: `left shift of 32768 by 16 places cannot be represented in type 'int'`.

Impact: same class as above. Fix: make `usage_page` unsigned or cast before shifting.

Reproduce either: `docker run <image> /mayhem/fuzz_hid_descriptor-standalone mayhem/fuzz_hid_descriptor/known-findings/<file>.bin`
