// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                          Static Function Declarations
// -----------------------------------------------------------------------------

#include <assert.h>
#include <string.h>

#include "esp_core_dump.h"
#include "esp_crash_http.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"

#include "spi_flash_mmap.h"

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Static Variables
// -----------------------------------------------------------------------------

static const char *TAG = "esp_crash";

// -----------------------------------------------------------------------------
//                          Public Function Definitions
// -----------------------------------------------------------------------------

esp_err_t esp_crash_erase_coredump()
{
    const esp_partition_t *core_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);

    if (!core_part) {
        ESP_LOGE(TAG, "No corepart found");
        return ESP_FAIL;
    }

    esp_err_t res = esp_partition_erase_range(core_part, 0, core_part->size);
    if (res == ESP_OK) {
        ESP_LOGI(TAG, "coredump erased successfully");
    } else {
        ESP_LOGE(TAG, "coredump partition erase res: %s", esp_err_to_name(res));
    }
    return res;
}

esp_err_t upload_coredump(const char *url, const char *filename)
{

    size_t out_size = 0;
    size_t out_addr = 0;
    esp_err_t ret = esp_core_dump_image_get(&out_addr, &out_size);
    if (ret != ESP_ERR_INVALID_SIZE)
        ESP_LOGD(TAG, "coredump ret: %d %s out_addr: %d out_size: %d", ret, esp_err_to_name(ret), out_addr, out_size);
    if (ret != ESP_OK)
        return ret;

    const uint32_t *data;
    spi_flash_mmap_handle_t handle;

    // ret = spi_flash_mmap(out_addr, out_size, SPI_FLASH_MMAP_DATA, (const void **)&data, &handle);

    const esp_partition_t *core_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);

    if (!core_part) {
        ESP_LOGE(TAG, "No corepart found");
        return ESP_FAIL;
    }

    ret = esp_partition_mmap(core_part, 0, out_size, SPI_FLASH_MMAP_DATA, (const void **)&data, &handle);

    ESP_LOGE(TAG, "mmap res: %s", esp_err_to_name(ret));

    if (ret != ESP_OK)
        return ret;

    ret = esp_crash_http_post(url, filename, (const char *)data, (int)out_size);

    spi_flash_munmap(handle);
    ESP_LOGE(TAG, "http res: %s", esp_err_to_name(ret));
    return ret;
}

bool esp_crash_coredump_available()
{
    size_t out_size = 0;
    size_t out_addr = 0;
    esp_err_t ret = esp_core_dump_image_get(&out_addr, &out_size);
    ESP_LOGD(TAG, "coredump ret: %d %s out_addr: %d out_size: %d", ret, esp_err_to_name(ret), out_addr, out_size);
    return ret == ESP_OK;
}

// -----------------------------------------------------------------------------
//                          Static Function Definitions
// -----------------------------------------------------------------------------
