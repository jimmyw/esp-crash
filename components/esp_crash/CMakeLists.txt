
message(STATUS "[MAIN] Project name: " ${PROJECT_NAME})
message(STATUS "[MAIN] Project version: " ${PROJECT_VER})


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

target_compile_options(${COMPONENT_LIB} PRIVATE "-DPROJECT_NAME=\"esp-crash-example\"" "-DPROJECT_VER=\"${PROJECT_VER}\"")
