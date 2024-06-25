DROP TABLE crash;
CREATE TABLE device (device_id SERIAL PRIMARY KEY, ext_device_id TEXT UNIQUE, alias TEXT);
CREATE TABLE crash (crash_id SERIAL PRIMARY KEY, "date" TIMESTAMP, project_name TEXT, project_ver TEXT, crash_dmp BYTEA,  device_id INTEGER REFERENCES device(device_id) NOT NULL);
CREATE TABLE elf_file (elf_file_id SERIAL PRIMARY KEY, "date" TIMESTAMP, project_name TEXT, project_ver TEXT, elf_file BYTEA);
CREATE TABLE project_auth (project_auth_id SERIAL PRIMARY KEY, "date" TIMESTAMP, project_name TEXT, github TEXT);
