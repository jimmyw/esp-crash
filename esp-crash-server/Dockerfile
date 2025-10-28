# syntax=docker/dockerfile:1.4
FROM python:3.13

RUN apt-get update && apt-get -y install libpq-dev python-dev-is-python3 git wget flex bison gperf python3 python3-pip python3-venv cmake ninja-build ccache libffi-dev libssl-dev dfu-util libusb-1.0-0

WORKDIR /root

RUN mkdir -p ~/esp; cd ~/esp; git clone --branch release/v5.4 --recursive https://github.com/espressif/esp-idf.git

RUN cd ~/esp/esp-idf; ./install.sh esp32,esp32s2,esp32s3

WORKDIR /setup
COPY requirements.txt /setup
RUN pip3 install -r requirements.txt

WORKDIR /code
ENV FLASK_APP server.py
ENV FLASK_ENV production
ENV FLASK_RUN_PORT 8000
ENV FLASK_RUN_HOST 0.0.0.0

ENV IDF_PYTHON_ENV_PATH=/root/.espressif/python_env/idf5.4_py3.13_env
ENV IDF_PATH=/root/esp/esp-idf
ENV OPENOCD_SCRIPTS=/root/.espressif/tools/openocd-esp32/v0.12.0-esp32-20250707/openocd-esp32/share/openocd/scripts
ENV ESP_IDF_VERSION=5.4
ENV PATH=/root/esp/esp-idf/components/espcoredump:/root/esp/esp-idf/components/partition_table:/root/esp/esp-idf/components/app_update:/root/.espressif/tools/xtensa-esp-elf-gdb/16.3_20250913/xtensa-esp-elf-gdb/bin:/root/.espressif/tools/riscv32-esp-elf-gdb/16.3_20250913/riscv32-esp-elf-gdb/bin:/root/.espressif/tools/xtensa-esp-elf/esp-14.2.0_20250730/xtensa-esp-elf/bin:/root/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20250730/riscv32-esp-elf/bin:/root/.espressif/tools/esp32ulp-elf/2.38_20240113/esp32ulp-elf/bin:/root/.espressif/tools/openocd-esp32/v0.12.0-esp32-20250707/openocd-esp32/bin:/root/.espressif/python_env/idf5.4_py3.13_env/bin:/root/esp/esp-idf/tools:PATH=/root/esp/esp-idf/components/espcoredump:/root/esp/esp-idf/components/partition_table:/root/esp/esp-idf/components/app_update:/root/.espressif/tools/xtensa-esp-elf-gdb/14.2_20240403/xtensa-esp-elf-gdb/bin:/root/.espressif/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin:/root/.espressif/tools/riscv32-esp-elf/esp-13.2.0_20230928/riscv32-esp-elf/bin:/root/.espressif/tools/esp32ulp-elf/2.35_20220830/esp32ulp-elf/bin:/root/.espressif/tools/openocd-esp32/v0.12.0-esp32-20240318/openocd-esp32/bin:/root/.espressif/tools/xtensa-esp-elf-gdb/14.2_20240403/xtensa-esp-elf-gdb/bin:/root/.espressif/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin:/root/.espressif/tools/riscv32-esp-elf/esp-13.2.0_20230928/riscv32-esp-elf/bin:/root/.espressif/tools/esp32ulp-elf/2.35_20220830/esp32ulp-elf/bin:/root/.espressif/tools/openocd-esp32/v0.12.0-esp32-20240318/openocd-esp32/bin:/root/esp/esp-idf/components/espcoredump:/root/esp/esp-idf/components/partition_table:/root/esp/esp-idf/components/app_update:/root/.espressif/tools/xtensa-esp-elf-gdb/12.1_20221002/xtensa-esp-elf-gdb/bin:/root/.espressif/tools/xtensa-esp32-elf/esp-12.2.0_20230208/xtensa-esp32-elf/bin:/root/.espressif/tools/xtensa-esp32s2-elf/esp-12.2.0_20230208/xtensa-esp32s2-elf/bin:/root/.espressif/tools/xtensa-esp32s3-elf/esp-12.2.0_20230208/xtensa-esp32s3-elf/bin:/root/.espressif/tools/riscv32-esp-elf/esp-12.2.0_20230208/riscv32-esp-elf/bin:/root/.espressif/tools/esp32ulp-elf/2.35_20220830/esp32ulp-elf/bin:/root/.espressif/tools/openocd-esp32/v0.12.0-esp32-20230419/openocd-esp32/bin:/root/.espressif/python_env/idf5.2_py3.10_env/bin:/root/esp/esp-idf/tools:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EXPOSE 8000

ENV FLASK_ENV development
CMD ["flask", "--app", "server", "run", "--debug"]
#CMD ["gunicorn"  , "-b", "0.0.0.0:8000", "wsgi:app"]
