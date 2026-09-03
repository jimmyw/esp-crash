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


# --- reports with no esp-coredump section headers ---------------------------
#
# What a vendor-neutral descriptor produces: a plain
# `-ex "thread apply all bt full"` GDB report. Verbatim from the arm-none-eabi
# package decoding a real EFR32 core (crash 116136), trimmed of its register
# dump. Note that GDB prints the current frame once when it opens the core and
# again under "Thread 1", which is exactly the repetition the fallback must not
# fold into the signature.
_ARM_PLAIN_REPORT = """\
warning: found thread with pid 0, assigned replacement Target Id: process 1
[New process 1]
#0  0x000053ca in cli_crash (arguments=<optimized out>) at src/app_cli.c:791

Thread 1 (process 1):
#0  0x000053ca in cli_crash (arguments=<optimized out>) at src/app_cli.c:791
        v = 0
        type = 1 '\\001'
#1  0x00000000 in ?? ()
No symbol table info available.
Backtrace stopped: previous frame identical to this frame (corrupt stack?)
"""


def test_plain_gdb_report_without_section_headers_is_signed():
    """Without this, a non-Espressif toolchain's crashes could never be grouped:
    no signature means no crash_relation, so no dedup, tags or AI review."""
    sig = compute_signature(_ARM_PLAIN_REPORT)
    assert sig is not None
    assert len(sig) == 64


def test_repeated_backtrace_block_is_not_counted_twice():
    """GDB echoes the current frame before the per-thread listing. The
    signature must come from one backtrace block, not the concatenation."""
    from app.crash_signature import _stack_frames

    assert _stack_frames(_ARM_PLAIN_REPORT) == ["cli_crash"]


def test_second_thread_does_not_extend_the_signature():
    """A multi-threaded report lists every thread; only the crashing thread's
    stack belongs in the fingerprint, matching what CURRENT THREAD STACK gives
    on the esp-coredump path."""
    from app.crash_signature import _stack_frames

    dump = (
        "#0  0x1 in crashing_fn (x=1) at a.c:1\n"
        "#1  0x2 in caller_fn (y=2) at a.c:2\n"
        "\nThread 2 (process 2):\n"
        "#0  0x3 in idle_task (z=3) at b.c:3\n"
        "#1  0x4 in other_fn (w=4) at b.c:4\n"
    )
    assert _stack_frames(dump) == ["crashing_fn", "caller_fn"]


def test_plain_report_fallback_does_not_sign_a_decode_failure():
    """The fallback must not turn an error message into a signature - an
    esp-coredump traceback has no `#N name (` lines at all."""
    assert compute_signature(
        "espcoredump.py v1.17.1\n"
        "Traceback (most recent call last):\n"
        '  File "/usr/local/bin/esp-coredump", line 8, in <module>\n'
        "    sys.exit(main())\n"
    ) is None


def test_plain_report_fallback_ignores_unsymbolicated_frames():
    """`?? ()` frames carry no function name, so a stripped backtrace stays
    unsigned rather than collapsing every such crash into one bogus group."""
    assert compute_signature(
        "#0  0x400d2f9a in ?? ()\n"
        "#1  0x400d3011 in ?? ()\n"
    ) is None
