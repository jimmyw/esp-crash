#pragma once

// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------
#include <esp_err.h>

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------
extern COREDUMP_DRAM_ATTR char crash_identifier[128];

// -----------------------------------------------------------------------------
//                          Public Function Declarations
// -----------------------------------------------------------------------------
const char *esp_crash_identifier_device_id();
esp_err_t esp_crash_identifier_setup();
esp_err_t esp_crash_identifier_setup_with_device(const char *device_id);
