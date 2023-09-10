
// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------

#include <assert.h>
#include <string.h>

#include "esp_core_dump.h"
#include "esp_crash_http.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"

#include "spi_flash_mmap.h"

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

#define RET_RETURN(x)                                                     \
    {                                                                     \
        esp_err_t RETX = (x);                                             \
        if (RETX != ESP_OK) {                                             \
            ESP_LOGE(TAG, "Error %x in %s:%d", RETX, __FILE__, __LINE__); \
            return RETX;                                                  \
        }                                                                 \
    }

// -----------------------------------------------------------------------------
//                          Static Function Declarations
// -----------------------------------------------------------------------------
static esp_err_t crash_dmp_handler(httpd_req_t *req);

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Static Variables
// -----------------------------------------------------------------------------
static const char *TAG = "esp_crash_webserver";

static const httpd_uri_t crash_dmp = {.uri = "/crash.dmp", .method = HTTP_GET, .handler = crash_dmp_handler, .user_ctx = NULL};

// -----------------------------------------------------------------------------
//                          Public Function Definitions
// -----------------------------------------------------------------------------

esp_err_t esp_crash_webserver_start(httpd_handle_t handle)
{
    return httpd_register_uri_handler(handle, &crash_dmp);
}

// -----------------------------------------------------------------------------
//                          Static Function Definitions
// -----------------------------------------------------------------------------

static esp_err_t crash_dmp_handler(httpd_req_t *req)
{
    ESP_LOGD(TAG, "GET crash.dmp Requested");

    RET_RETURN(httpd_resp_set_type(req, "application/octet-stream"));

    size_t out_size = 0;
    size_t out_addr = 0;
    esp_err_t ret = esp_core_dump_image_get(&out_addr, &out_size);
    ESP_LOGD(TAG, "coredump ret: %d %s out_addr: %d out_size: %d", ret, esp_err_to_name(ret), out_addr, out_size);
    if (ret != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No coredump found");

    const uint32_t *data;
    spi_flash_mmap_handle_t handle;

    // ret = spi_flash_mmap(out_addr, out_size, SPI_FLASH_MMAP_DATA, (const void **)&data, &handle);

    const esp_partition_t *core_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);

    if (!core_part) {
        ESP_LOGE(TAG, "No corepart found");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No coredump partition found");
    }

    ret = esp_partition_mmap(core_part, 0, out_size, SPI_FLASH_MMAP_DATA, (const void **)&data, &handle);

    ESP_LOGE(TAG, "mmap res: %s", esp_err_to_name(ret));

    if (ret != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Unable to mmap crashdump");

    ret = httpd_resp_send(req, (const char *)data, out_size);

    spi_flash_munmap(handle);

    return ret;
}
