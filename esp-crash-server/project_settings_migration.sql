-- Migration script to add per-project settings support.
-- Run this against existing ESP-Crash installations (fresh installs get it from db_schema.sql).

CREATE TABLE IF NOT EXISTS project_settings (
    project_name TEXT PRIMARY KEY,
    device_url_template TEXT
);
