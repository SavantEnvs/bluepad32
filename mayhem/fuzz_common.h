// Shared scaffolding for the Mayhem fuzz harnesses: the BTstack/HCI bring-up and the mock platform the
// library expects its host application to provide (same pattern as tests/test_uni_hid_parser_synthetic.c).
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <btstack.h>
#include <btstack_memory.h>
#include <btstack_run_loop.h>
#include <btstack_run_loop_base.h>
#include <btstack_run_loop_posix.h>
#include <hci.h>
#include <hci_transport.h>
#include <l2cap.h>

#include "bt/uni_bt_defines.h"
#include "controller/uni_controller.h"
#include "controller/uni_controller_type.h"
#include "platform/uni_platform.h"
#include "sdkconfig.h"
#include "uni_common.h"
#include "uni_config.h"
#include "uni_hid_device.h"
#include "uni_log.h"
#include "uni_property.h"
#include "uni_virtual_device.h"

void uni_logv(const char* fmt, va_list args) {
    (void)fmt;
    (void)args;
}

static void dummy_transport_register_packet_handler(void (*handler)(uint8_t packet_type,
                                                                    uint8_t* packet,
                                                                    uint16_t size)) {
    (void)handler;
}

static const hci_transport_t g_dummy_transport = {
    .name = "dummy_fuzz",
    .register_packet_handler = dummy_transport_register_packet_handler,
};

static void mock_platform_init(int argc, const char** argv) {
    (void)argc;
    (void)argv;
}
static void mock_platform_on_init_complete(void) {}
static uni_error_t mock_platform_on_device_discovered(bd_addr_t addr, const char* name, uint16_t cod, uint8_t rssi) {
    (void)addr;
    (void)name;
    (void)cod;
    (void)rssi;
    return UNI_ERROR_SUCCESS;
}
static void mock_platform_on_device_connected(uni_hid_device_t* d) {
    (void)d;
}
static void mock_platform_on_device_disconnected(uni_hid_device_t* d) {
    (void)d;
}
static uni_error_t mock_platform_on_device_ready(uni_hid_device_t* d) {
    (void)d;
    return UNI_ERROR_SUCCESS;
}
static void mock_platform_on_controller_data(uni_hid_device_t* d, uni_controller_t* ctl) {
    (void)d;
    (void)ctl;
}
static void mock_platform_on_oob_event(uni_platform_oob_event_t event, void* data) {
    (void)event;
    (void)data;
}
static const uni_property_t* mock_platform_get_property(uni_property_idx_t idx) {
    (void)idx;
    return NULL;
}

static struct uni_platform g_mock_platform = {
    .name = "fuzz_mock",
    .init = mock_platform_init,
    .on_init_complete = mock_platform_on_init_complete,
    .on_device_discovered = mock_platform_on_device_discovered,
    .on_device_connected = mock_platform_on_device_connected,
    .on_device_disconnected = mock_platform_on_device_disconnected,
    .on_device_ready = mock_platform_on_device_ready,
    .on_controller_data = mock_platform_on_controller_data,
    .on_oob_event = mock_platform_on_oob_event,
    .get_property = mock_platform_get_property,
};

struct uni_platform* uni_get_platform(void) {
    return &g_mock_platform;
}

static void fuzz_stack_init(void) {
    btstack_memory_init();
    btstack_run_loop_init(btstack_run_loop_posix_get_instance());
    uni_property_init();
    uni_virtual_device_init();
    uni_virtual_device_set_enabled(true);
    hci_init(&g_dummy_transport, NULL);
    l2cap_init();
}

// Fresh device table and no leftover run-loop timers: each input starts from the same state.
static void fuzz_reset_state(void) {
    btstack_run_loop_base_timers = NULL;
    uni_hid_device_setup();
}

typedef struct {
    uint16_t vid;
    uint16_t pid;
    uint32_t cod;
} fuzz_controller_t;

// One representative device per report-parser implementation (VID/PID pairs taken from the
// controller table in uni_controller_list.h), plus keyboard/mouse by Class of Device and unknown ids.
static const fuzz_controller_t g_fuzz_controllers[] = {
    {0x054c, 0x0268, 0},  // PS3
    {0x054c, 0x09cc, 0},  // DualShock 4
    {0x054c, 0x0ce6, 0},  // DualSense
    {0x054c, 0x0c5e, 0},  // PS3-like clone family
    {0x054c, 0x03d5, 0},  // PS Move
    {0x045e, 0x02e0, 0},  // Xbox One (BT)
    {0x045e, 0x028e, 0},  // Xbox 360 wired family
    {0x057e, 0x2006, 0},  // Switch Joy-Con L
    {0x057e, 0x2007, 0},  // Switch Joy-Con R
    {0x057e, 0x2009, 0},  // Switch Pro
    {0x057e, 0x0306, 0},  // Wii remote
    {0x28de, 0x1106, 0},  // Steam controller
    {0x18d1, 0x9400, 0},  // Stadia
    {0x1949, 0x0401, 0},  // Android family
    {0x20d6, 0x6271, 0},  // PowerA / Android-like
    {0x15e4, 0x0132, 0},  // iCade-like
    {0x2dc8, 0x6100, 0},  // 8BitDo
    {0x2836, 0x0001, 0},  // OUYA
    {0x0111, 0x1420, 0},  // Nimbus
    {0x3250, 0x1001, 0},  // Atari
    {0x2e8a, 0x10c6, 0},  // SInput
    {0x0a5c, 0x4502, 0},  // generic gamepad
    {0xdead, 0xbeef, 0},  // unknown id
    {0x05ac, 0x022c, UNI_BT_COD_MAJOR_PERIPHERAL | UNI_BT_COD_MINOR_KEYBOARD},
    {0x05ac, 0x030d, UNI_BT_COD_MAJOR_PERIPHERAL | UNI_BT_COD_MINOR_MICE},
    {0x05ac, 0x0304, UNI_BT_COD_MAJOR_PERIPHERAL | UNI_BT_COD_MINOR_MICE},
};
#define FUZZ_NUM_CONTROLLERS (sizeof(g_fuzz_controllers) / sizeof(g_fuzz_controllers[0]))

static void fuzz_setup_device(uni_hid_device_t* d, uint8_t selector) {
    const fuzz_controller_t* c = &g_fuzz_controllers[selector % FUZZ_NUM_CONTROLLERS];
    fuzz_reset_state();
    uni_hid_device_init(d);
    d->vendor_id = c->vid;
    d->product_id = c->pid;
    d->cod = c->cod;
    uni_hid_device_guess_controller_type_from_pid_vid(d);
    if (d->report_parser.setup) {
        d->report_parser.setup(d);
    }
}

#endif  // MAYHEM_FUZZ_COMMON_H
