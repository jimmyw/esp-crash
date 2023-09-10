| Supported Targets | ESP32 | ESP32-C3 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- |

# ESP-Crash Example (`esp-crash-example`)

This example is tied to esp-crash, that can be found at https://esp-crash.wennlund.nu/ that is a free service to monitor and display crashes.

## How to use example

This example uses a coredump parition, name coredump. The build in crash-handler will wire a crash to this parition if you enable CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y in your sdkconfig.

Before you can see your crashes uploaded, you need to access https://esp-crash.wennlund.nu/ with your github account, and register a new unique PROJECT_NAME. After you have registered it, you can add additional team members that also can examine the crahes.

## ESP-Crash Identifier

Using esp_crash_identifier_setup() you will add an identifier to ram, that will always be included in your crashdump. This identifier is in the format:

ESP_CRASH:<PROJECT_NAME>;<PROJECT_VER>;<DEVICE_ID>;

Example:

ESP_CRASH:esp-crash-example;8e8e8df-5.1;6941729232066;

This is critical for our backend to pick up, just make it available to your registred project, and know what build file to match up

## Uploading coredumps

Using esp_err_t upload_coredump(const char *url, const char *filename) as an example to upload the coredump directly from a parition to a server. This will read the flash parition and send it as raw data, nothing more nothing less.
Upload your crashes to "https://esp-crash.wennlund.nu/dump" if you like to have a free store for your crashes.

## Downloading coredumpos

Using esp_err_t esp_crash_webserver_start(httpd_handle_t handle); you can register the /crash.dmp webserver endpoint. Curling this address will download the last crash if available. After downloading this crash, you can upload it again to "https://esp-crash.wennlund.nu/dump" if you like.

## Inverval crash upload

Using esp_err_t esp_crash_upload_timer_init(); you will enable a 60s interval timer, that will try to find a existing core dump, and upload if possible. On success the coredump parition will be erased.

## Uploading build files

To be able to examine your crashes, you also need to upload the elf binary, with debugging symbols. This can be done with this oneliner:

```
curl “https://esp-crash.wennlund.nu/upload_elf?project_name=esp-crash-example&project_ver=$VERSION” -F file=build/esp-crash-example.elf
```

Make sure $VERSION is matching the same PRJECT_VER in your build. This command can easily be added your CI-System

### Cli commands


```
coredump_crash
  Crash the esp32

coredump_erase
  Erase cordump partition

coredump_upload  [-e] [url] [filename]
  Upload core dump to server
           url  Url to send to
      filename  Filename
   -e, --erase  Erase after successful upload
```


## Example Output


```
```

## Whats upcoming?

Im working on an interactive in browser gdb debug session. Its going to be awsome!