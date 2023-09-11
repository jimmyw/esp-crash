
| Supported Targets | ESP32 | ESP32-C3 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- |

# ESP-Crash Example (`esp-crash-example`)

This example is tied to esp-crash, which can be found at https://esp-crash.wennlund.nu/. It is a free service to monitor and display crashes.

## How to use example

This example uses a coredump partition, named coredump. The built-in crash-handler will write a crash to this partition if you enable CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y in your sdkconfig.

To add a coredump partition to your esp-idf partition.csv file, you can use the following example:

```
# Name,   Type, SubType, Offset,  Size, Flags
nvs,      data, nvs,     0x9000,  0x5000,
phy_init, data, phy,     0xe000,  0x2000,
factory,  app,  factory, 0x10000, 1M,
coredump, data, coredump, ,       128K,
```
This will create a 64K coredump partition. If you have a lot of tasks, you need to increase the size to fit all data.

Before you can see your uploaded crashes, you need to access https://esp-crash.wennlund.nu/ with your GitHub account, and register a new unique PROJECT_NAME. After you have registered it, you can add additional team members who can also examine the crashes.

## ESP-Crash Identifier

Using
```
esp_err_t esp_crash_identifier_setup()
```
you can add an identifier to RAM, which will always be included in your crash dump. This identifier is in the format:

```
ESP_CRASH:<PROJECT_NAME>;<PROJECT_VER>;<DEVICE_ID>;
```
Example:
```
ESP_CRASH:esp-crash-example;8e8e8df-5.1;6941729232066;
```
This is critical for our backend to pick up, just make it available to your registered project, and know what build file to match up.

## Uploading coredumps

Use 
```
esp_err_t upload_coredump(const char *url, const char *filename)
```
to upload the coredump directly from a partition to a server. This will read the flash partition and send it as raw data. Upload your crashes to "https://esp-crash.wennlund.nu/dump" if you like to have a free store for your crashes.

## Downloading coredumps

Use 
```
esp_err_t esp_crash_webserver_start(httpd_handle_t handle)
```
to register the /crash.dmp webserver endpoint. Curling this address will download the last crash if available. After downloading this crash, you can upload it again to "https://esp-crash.wennlund.nu/dump" if you like.

## Interval crash upload

Use 
```
esp_err_t esp_crash_upload_timer_init()
```
to enable a 60s interval timer, that will try to find an existing core dump, and upload if possible. On success, the coredump partition will be erased.

## Uploading build files

To be able to examine your crashes, you also need to upload the elf binary, with debugging symbols. This can be done with this one-liner:

```
curl “https://esp-crash.wennlund.nu/upload_elf?project_name=esp-crash-example&project_ver=$VERSION” -F file=build/esp-crash-example.elf
```

Ensure $VERSION matches the same PROJECT_VER in your build. This command can easily be added to your CI system.

### CLI commands
```
coredump_crash
  Crash the esp32

coredump_erase
  Erase coredump partition

coredump_upload  [-e] [url] [filename]
  Upload core dump to server
           url  Url to send to
      filename  Filename
   -e, --erase  Erase after successful upload
```

## Example Output



## What's upcoming?

Im working on an interactive in browser gdb debug session. Its going to be awsome!
