
// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------
#include <assert.h>
#include <string.h>

#include "esp_console.h"
#include "esp_crash.h"
#include "esp_log.h"

#include "argtable3/argtable3.h"
#include "linenoise/linenoise.h"

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

static struct {
    struct arg_str *url;
    struct arg_str *filename;
    struct arg_lit *erase;
    struct arg_end *end;
} upload_args;

// -----------------------------------------------------------------------------
//                          Static Function Declarations
// -----------------------------------------------------------------------------
static int cmd_upload(int argc, char **argv);
static int cmd_crash(int argc, char **argv);
static int cmd_erase(int argc, char **argv);

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Static Variables
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                          Public Function Definitions
// -----------------------------------------------------------------------------

esp_err_t esp_crash_cli_init()
{
    upload_args.url = arg_str0(NULL, NULL, "url", "Url to send to");
    upload_args.filename = arg_str0(NULL, NULL, "filename", "Filename");
    upload_args.erase = arg_lit0("e", "erase", "Erase after successful upload");
    upload_args.end = arg_end(2);

    const esp_console_cmd_t crash_cmd = {
        .command = "coredump_crash",
        .help = "Crash the esp32",
        .hint = NULL,
        .func = &cmd_crash,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&crash_cmd));

    const esp_console_cmd_t upload_cmd = {
        .command = "coredump_upload", .help = "Upload core dump to server", .hint = NULL, .func = &cmd_upload, .argtable = &upload_args};
    ESP_ERROR_CHECK(esp_console_cmd_register(&upload_cmd));

    const esp_console_cmd_t erase_cmd = {.command = "coredump_erase", .help = "Erase cordump partition", .hint = NULL, .func = &cmd_erase};
    ESP_ERROR_CHECK(esp_console_cmd_register(&erase_cmd));

    return ESP_OK;
}

// -----------------------------------------------------------------------------
//                          Static Function Definitions
// -----------------------------------------------------------------------------

static int cmd_upload(int argc, char **argv)
{

    int nerrors = arg_parse(argc, argv, (void **)&upload_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, upload_args.end, argv[0]);
        return 1;
    }
    const char *url = upload_args.url->count > 0 ? upload_args.url->sval[0] : CONFIG_ESP_CRASH_DEFAULT_URL;
    const char *filename = upload_args.filename->count > 0 ? upload_args.filename->sval[0] : CONFIG_ESP_CRASH_DEFAULT_FILENAME;
    int res = upload_coredump(url, filename);

    if (upload_args.erase->count > 0 && res == 0) {
        esp_crash_erase_coredump();
    }

    return res;
}

static int cmd_crash(int argc, char **argv)
{
    assert(0);
    abort();
    return 0;
}

static int cmd_erase(int argc, char **argv)
{
    return esp_crash_erase_coredump();
}
