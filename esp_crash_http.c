

// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------
#include <assert.h>
#include <string.h>

#include "esp_crash_http.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

#define PART_BOUND "---------------------------9051914041544843365972754266"
#define CRLN "\r\n"

// -----------------------------------------------------------------------------
//                          Static Function Declarations
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------
static const char *TAG = "esp_crash_http";

// -----------------------------------------------------------------------------
//                                Static Variables
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                          Public Function Definitions
// -----------------------------------------------------------------------------

// Writes a file, using a multi part form request
esp_err_t esp_crash_http_post(const char *url, const char *filename, const char *data, int data_size)
{
    ESP_LOGI(TAG, "Going to post: %d bytes to url: '%s' filename: '%s'", data_size, url, filename);
    char buffer[256] = {0};
    int bytes_sent = 0;
    int header_bytes = snprintf(buffer, sizeof(buffer),
                                "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", filename);

    if (header_bytes >= sizeof(buffer)) {
        ESP_LOGE(TAG, "Buffer overflow");
        return ESP_FAIL;
    }

    esp_http_client_config_t config = {
        .url = url,
        .use_global_ca_store = true,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    // esp_http_client_set_post_field(client, data, data_size);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Referer", url);
    esp_http_client_set_header(client, "Origin", url);
    esp_http_client_set_header(client, "Content-Type", "multipart/form-data; boundary=" PART_BOUND);
    esp_http_client_set_url(client, url);

    const int content_size = 2 + strlen(PART_BOUND) + 2 + header_bytes + data_size + 2 + 2 + strlen(PART_BOUND) + 2 + 2;

    ESP_LOGD(TAG, "Calculated size size: %d + %d + %d + %d = %d", header_bytes, strlen(PART_BOUND), data_size, strlen(PART_BOUND), content_size);

    // GET
    esp_err_t err = esp_http_client_open(client, content_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    // Write part bundary
    bytes_sent += esp_http_client_write(client, "--", 2);
    bytes_sent += esp_http_client_write(client, PART_BOUND, strlen(PART_BOUND));
    bytes_sent += esp_http_client_write(client, CRLN, 2);

    // Write part header
    bytes_sent += esp_http_client_write(client, buffer, header_bytes);

    // Write data
    bytes_sent += esp_http_client_write(client, data, data_size);
    ESP_LOGI(TAG, "Wrote %d bytes of data", data_size);
    bytes_sent += esp_http_client_write(client, CRLN, 2);

    // Write part boundary
    bytes_sent += esp_http_client_write(client, "--", 2);
    bytes_sent += esp_http_client_write(client, PART_BOUND, strlen(PART_BOUND));
    bytes_sent += esp_http_client_write(client, "--", 2);
    bytes_sent += esp_http_client_write(client, CRLN, 2);

    ESP_LOGI(TAG, "Wrote total %d bytes of %d", bytes_sent, content_size);

    esp_http_client_fetch_headers(client);

    // Read the response..
    int read_bytes = esp_http_client_read_response(client, buffer, sizeof(buffer));

    ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %" PRIu64 " '%.*s'", esp_http_client_get_status_code(client),
             esp_http_client_get_content_length(client), read_bytes, buffer);

    // Check for http error.
    if (esp_http_client_get_status_code(client) >= 500) {
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    esp_http_client_cleanup(client);
    return ESP_OK;
}

// -----------------------------------------------------------------------------
//                          Static Function Definitions
// -----------------------------------------------------------------------------
