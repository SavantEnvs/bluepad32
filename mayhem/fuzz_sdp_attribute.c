// Fuzzes the SDP attribute parsing of a remote Bluetooth device (PnP vendor/product id and the HID report
// descriptor list), fed the way BTstack's SDP client delivers it: one SDP_EVENT_QUERY_ATTRIBUTE_VALUE per byte.
// Input: byte 0 selects the attribute (bits 0..1) and the handler, the rest is the encoded SDP data element.
#include "fuzz_common.h"

#include <bluetooth_data_types.h>
#include <classic/sdp_util.h>

#include "bt/uni_bt_sdp.h"

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
    fuzz_stack_init();
    return 0;
}

static const uint16_t k_attributes[] = {
    BLUETOOTH_ATTRIBUTE_HID_DESCRIPTOR_LIST,
    BLUETOOTH_ATTRIBUTE_VENDOR_ID,
    BLUETOOTH_ATTRIBUTE_PRODUCT_ID,
    BLUETOOTH_ATTRIBUTE_HID_DESCRIPTOR_LIST,
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2 || size > 1 + 600) {
        return -1;
    }
    uint8_t sel = data[0];
    uint16_t attribute_id = k_attributes[sel & 3];
    void (*handler)(uint8_t, uint16_t, uint8_t*, uint16_t) =
        (attribute_id == BLUETOOTH_ATTRIBUTE_HID_DESCRIPTOR_LIST) ? uni_handle_sdp_hid_query_result
                                                                  : uni_handle_sdp_pid_query_result;
    const uint8_t* attr = data + 1;
    uint16_t attr_len = (uint16_t)(size - 1);

    fuzz_reset_state();
    bd_addr_t addr = {0x44, 0x55, 0x66, 0x77, 0x88, 0x01};
    uni_hid_device_t* d = uni_hid_device_create(addr);
    if (d == NULL) {
        return -1;
    }
    // Incoming devices never try to open an L2CAP channel when the SDP query completes.
    uni_hid_device_set_incoming(d, true);
    uni_bt_sdp_set_device_for_test(d);

    // Same two-phase contract as BTstack's sdp_parser_process_byte(): while the data element header is
    // read the reported attribute length is 0, afterwards it is the full length.
    uint32_t header_len = de_get_header_size(attr);
    uint8_t pkt[11];
    pkt[0] = SDP_EVENT_QUERY_ATTRIBUTE_VALUE;
    pkt[1] = 9;
    little_endian_store_16(pkt, 2, 1);
    little_endian_store_16(pkt, 4, attribute_id);
    for (uint16_t offset = 0; offset < attr_len; offset++) {
        little_endian_store_16(pkt, 6, (offset < header_len) ? 0 : attr_len);
        little_endian_store_16(pkt, 8, offset);
        pkt[10] = attr[offset];
        handler(HCI_EVENT_PACKET, 0, pkt, sizeof(pkt));
    }

    uni_bt_sdp_set_device_for_test(NULL);
    uni_hid_device_delete(d);
    btstack_run_loop_base_timers = NULL;
    return 0;
}
