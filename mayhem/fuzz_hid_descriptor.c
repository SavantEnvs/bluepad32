// Fuzzes the HID report-descriptor handling: a remote device's descriptor is stored with
// uni_hid_device_set_hid_descriptor() and then drives the descriptor-based input report parsing.
// Input: byte 0 selects the controller type, bytes 1-2 are the descriptor length (little endian),
// followed by the descriptor and then the input report parsed with it.
#include "fuzz_common.h"

#include "parser/uni_hid_parser.h"

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
    fuzz_stack_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static uni_hid_device_t d;
    if (size < 3) {
        return -1;
    }
    uint16_t desc_len = (uint16_t)(data[1] | (data[2] << 8));
    if (desc_len > size - 3) {
        return -1;
    }
    const uint8_t* desc = data + 3;
    const uint8_t* report = desc + desc_len;
    size_t report_len = size - 3 - desc_len;
    if (report_len > 512) {
        return -1;
    }

    fuzz_setup_device(&d, data[0]);
    uni_hid_device_set_hid_descriptor(&d, desc, desc_len);
    uni_hid_parse_input_report(&d, report, (uint16_t)report_len);
    btstack_run_loop_base_timers = NULL;
    return 0;
}
