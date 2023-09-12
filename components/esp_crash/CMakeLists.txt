idf_component_register(
    SRCS
        esp_crash.c
        esp_crash_cli.c
        esp_crash_http.c
        esp_crash_identifier.c
        esp_crash_upload_timer.c
        esp_crash_webserver.c
    INCLUDE_DIRS
        .
    REQUIRES
        console
        espcoredump
        mbedtls
        esp_event
        esp_http_client
        esp_http_server
        esp_partition
        esp_timer
        spi_flash
)

idf_build_get_property(project_ver PROJECT_VER)
idf_build_get_property(project_name PROJECT_NAME)

set_source_files_properties(
    SOURCE "esp_crash_identifier.c"
    PROPERTIES COMPILE_DEFINITIONS
    "PROJECT_VER=\"${project_ver}\"; PROJECT_NAME=\"${project_name}\""
)
