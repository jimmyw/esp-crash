// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------
#include <endian.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                          Static Function Declarations
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------

// STORE CRASH IDENTIFIER IN RAM, AND MAKE SURE ITS PART OF THE CORE DUMP
// example: ESP_CRASH ID: 'ESP_CRASH:esp-idf;8e8e8df-dirty;6941729232066;'
COREDUMP_DRAM_ATTR char crash_identifier[128];

// -----------------------------------------------------------------------------
//                                Static Variables
// -----------------------------------------------------------------------------

static const char *TAG = "esp_crash_identifier";

// -----------------------------------------------------------------------------
//                          Public Function Definitions
// -----------------------------------------------------------------------------

// OUR WAY TO FETCH AN UNIQUE IDENTIFIER FOR THIS SYSTEM
const char *esp_crash_identifier_device_id()
{
#if CONFIG_SOC_IEEE802154_SUPPORTED
    static char device_id[2 * 8 + 1]; // 64-bit MAC
#else
    static char device_id[2 * 6 + 1]; // 48-bit MAC
#endif

    if (!device_id[0]) {
        uint64_t chipmacid = 0LL;
        esp_efuse_mac_get_default((uint8_t *)(&chipmacid));
#if CONFIG_SOC_IEEE802154_SUPPORTED
        snprintf(device_id, sizeof(device_id), "%.16" PRIx64, bswap64(chipmacid));
#else
        snprintf(device_id, sizeof(device_id), "%.12" PRIx64, bswap64(chipmacid));
#endif
    }
    return device_id;
}

esp_err_t esp_crash_identifier_setup()
{
    // REGISTER A CRASH IDENTIFIER THAT WILL BE PROVIDED IN CRASHES UPLOADED REMOTELY.
    snprintf(crash_identifier, sizeof(crash_identifier), "ESP_CRASH:%s;%s;%s;", PROJECT_NAME, PROJECT_VER, esp_crash_identifier_device_id());
    ESP_LOGI(TAG, "ESP_CRASH ID: '%s'", crash_identifier);
    return ESP_OK;
}

// -----------------------------------------------------------------------------
//                          Static Function Definitions
// -----------------------------------------------------------------------------
