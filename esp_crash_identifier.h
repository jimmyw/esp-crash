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

// -----------------------------------------------------------------------------
//                          Public Function Declarations
// -----------------------------------------------------------------------------
esp_err_t esp_crash_identifier_setup();
const char *esp_crash_identifier_device_id();