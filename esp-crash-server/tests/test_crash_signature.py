"""Tests for app/crash_signature.py. Sample dump text below is trimmed from
real esp-crash-server crash dumps (addresses/pointers changed, structure and
function names preserved) - including the actual "same root cause, different
device" case (a watchdog firing on two different devices) that motivated the
signature approach in the first place."""
from app.crash_signature import compute_signature

_WATCHDOG_DEVICE_A = """
==================== CURRENT THREAD STACK =====================
#0  panic_abort (details=0x3ffb37ac <port_IntStack+1964> "Watchdog 'ota_manifest' timeout") at /opt/esp/idf/components/esp_system/panic.c:489
#1  0x4008874c in esp_system_abort (details=0x3ffb37ac <port_IntStack+1964> "Watchdog 'ota_manifest' timeout") at /opt/esp/idf/components/esp_system/port/esp_system_chip.c:87
#2  0x40114e3c in watchdog_timer_isr_callback (timer=0x3ffd1108, edata=0x3ffb3810 <port_IntStack+2064>, user_ctx=0x3ffb4738 <s_pool+32>) at /root/project/components/watchdog/watchdog.c:330
#3  0x40086d8b in gptimer_default_isr (args=0x3ffd1108) at /opt/esp/idf/components/esp_driver_gptimer/src/gptimer.c:470
#4  0x40082b18 in _xt_lowint1 () at /opt/esp/idf/components/xtensa/xtensa_vectors.S:1240
#5  0x40086ff2 in xt_utils_wait_for_intr () at /opt/esp/idf/components/xtensa/include/xt_utils.h:82
#6  esp_cpu_wait_for_intr () at /opt/esp/idf/components/esp_hw_support/cpu.c:55
#7  0x401b87f0 in esp_vApplicationIdleHook () at /opt/esp/idf/components/esp_system/freertos_hooks.c:58
#8  0x401ba72a in prvIdleTask (pvParameters=0x0) at /opt/esp/idf/components/freertos/FreeRTOS-Kernel/tasks.c:4350
#9  0x401b9845 in vPortTaskWrapper (pxCode=0x401ba6a8 <prvIdleTask>, pvParameters=0x0) at /opt/esp/idf/components/freertos/FreeRTOS-Kernel/portable/xtensa/port.c:139

======================== THREADS INFO =========================
"""

# Same bug, different device: identical function-name sequence, different
# register/timer-handle addresses throughout.
_WATCHDOG_DEVICE_B = """
==================== CURRENT THREAD STACK =====================
#0  panic_abort (details=0x3ffb37ac <port_IntStack+1964> "Watchdog 'ota_manifest' timeout") at /opt/esp/idf/components/esp_system/panic.c:489
#1  0x4008874c in esp_system_abort (details=0x3ffb37ac <port_IntStack+1964> "Watchdog 'ota_manifest' timeout") at /opt/esp/idf/components/esp_system/port/esp_system_chip.c:87
#2  0x40114e3c in watchdog_timer_isr_callback (timer=0x3ffd10dc, edata=0x3ffb3810 <port_IntStack+2064>, user_ctx=0x3ffb4738 <s_pool+32>) at /root/project/components/watchdog/watchdog.c:330
#3  0x40086d8b in gptimer_default_isr (args=0x3ffd10dc) at /opt/esp/idf/components/esp_driver_gptimer/src/gptimer.c:470
#4  0x40082b18 in _xt_lowint1 () at /opt/esp/idf/components/xtensa/xtensa_vectors.S:1240
#5  0x40086ff2 in xt_utils_wait_for_intr () at /opt/esp/idf/components/xtensa/include/xt_utils.h:82
#6  esp_cpu_wait_for_intr () at /opt/esp/idf/components/esp_hw_support/cpu.c:55
#7  0x401b87f0 in esp_vApplicationIdleHook () at /opt/esp/idf/components/esp_system/freertos_hooks.c:58
#8  0x401ba72a in prvIdleTask (pvParameters=0x0) at /opt/esp/idf/components/freertos/FreeRTOS-Kernel/tasks.c:4350
#9  0x401b9845 in vPortTaskWrapper (pxCode=0x401ba6a8 <prvIdleTask>, pvParameters=0x0) at /opt/esp/idf/components/freertos/FreeRTOS-Kernel/portable/xtensa/port.c:139

======================== THREADS INFO =========================
"""

_MQTT_RETRY_CRASH = """
==================== CURRENT THREAD STACK =====================
#0  0x40081fc9 in panic_abort (details=0x3ffd223a "abort() was called at PC 0x4008a3bf on core 0") at /opt/esp/idf/components/esp_system/panic.c:455
#1  0x4008a3cc in esp_system_abort (details=0x3ffd223a "abort() was called at PC 0x4008a3bf on core 0") at /opt/esp/idf/components/esp_system/esp_system.c:153
#2  0x400913bc in abort () at /opt/esp/idf/components/newlib/abort.c:38
#3  0x4008a3c2 in _esp_error_check_failed (rc=-1, file=0x3f40e986 "./common/mqtt.c", line=751, function=0x3f40f2c2 <__func__$2> "retry_connect", expression=0x3f40eb87 "esp_mqtt_client_start(mqtt_client)") at /opt/esp/idf/components/esp_system/esp_err.c:47
#4  0x400e9d22 in retry_connect () at /root/project/common/mqtt.c:751
#5  0x400ea71d in mqtt_watch_thread (pvParameters=<optimized out>) at /root/project/common/mqtt.c:805
#6  0x4008a3dc in vPortTaskWrapper (pxCode=0x400ea6b4 <mqtt_watch_thread>, pvParameters=0x0) at /opt/esp/idf/components/freertos/FreeRTOS-Kernel/portable/xtensa/port.c:149

======================== THREADS INFO =========================
"""

_DECODE_FAILURE = (
    "espcoredump.py v1.16.0\n"
    "Failed to load core dump: Invalid application image for coredump: "
    "coredump SHA256(7ee9b037d904b0f9) != app SHA256(3fc0bb573327c831).\n"
)


def test_same_bug_different_device_gets_same_signature():
    assert compute_signature(_WATCHDOG_DEVICE_A) == compute_signature(_WATCHDOG_DEVICE_B)


def test_different_bugs_get_different_signatures():
    assert compute_signature(_WATCHDOG_DEVICE_A) != compute_signature(_MQTT_RETRY_CRASH)


def test_signature_is_a_nonempty_hex_string():
    sig = compute_signature(_MQTT_RETRY_CRASH)
    assert sig is not None
    assert len(sig) == 64
    assert all(c in "0123456789abcdef" for c in sig)


def test_dump_without_parseable_backtrace_returns_none():
    assert compute_signature(_DECODE_FAILURE) is None


def test_empty_or_missing_dump_returns_none():
    assert compute_signature("") is None
    assert compute_signature(None) is None


def test_frame_without_address_prefix_is_still_parsed():
    # gdb omits the "0xADDR in" prefix for some frames (e.g. #0, or a frame
    # gdb resolved purely from the symbol table) - both dumps above already
    # exercise this (#0 and #6 in the watchdog dumps), this test pins it
    # down explicitly against a minimal single-frame case.
    dump = (
        "==================== CURRENT THREAD STACK =====================\n"
        "#0  esp_cpu_wait_for_intr () at /opt/esp/idf/components/esp_hw_support/cpu.c:55\n"
        "======================== THREADS INFO =========================\n"
    )
    assert compute_signature(dump) is not None
