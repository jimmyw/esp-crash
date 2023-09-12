
// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------
#include <assert.h>
#include <string.h>

#include "esp_crash.h"
#include "esp_crash_upload_timer.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                          Static Function Declarations
// -----------------------------------------------------------------------------

static void periodic_timer_callback(void *arg);

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Static Variables
// -----------------------------------------------------------------------------

static const char *TAG = "esp_crash_upload_timer";
static esp_timer_handle_t periodic_timer_handle = NULL;

// -----------------------------------------------------------------------------
//                          Public Function Definitions
// -----------------------------------------------------------------------------

esp_err_t esp_crash_upload_timer_init()
{
    if (!esp_crash_coredump_available()) {
        return ESP_OK;
    }

    // Handle coredump upload timer.
    const esp_timer_create_args_t periodic_coredump_check = {.callback = &periodic_timer_callback,
                                                             /* name is optional, but may help identify the timer when debugging */
                                                             .name = "upload_coredump"};
    ESP_ERROR_CHECK(esp_timer_create(&periodic_coredump_check, &periodic_timer_handle));
    esp_timer_start_periodic(periodic_timer_handle, 60 * 1000000);
    return ESP_OK;
}

// -----------------------------------------------------------------------------
//                          Static Function Definitions
// -----------------------------------------------------------------------------

static void periodic_timer_callback(void *arg)
{
    ESP_LOGD(TAG, "Upload coredump timer...");
    int res = upload_coredump(CONFIG_ESP_CRASH_DEFAULT_URL, CONFIG_ESP_CRASH_DEFAULT_FILENAME);

    if (res == 0) {
        ESP_LOGI(TAG, "Successful upload, erasing coredump");
        esp_crash_erase_coredump();
        esp_timer_delete(periodic_timer_handle);
    }
}
