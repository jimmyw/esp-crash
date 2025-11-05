DROP TABLE crash;
CREATE TABLE device (device_id SERIAL PRIMARY KEY, ext_device_id TEXT UNIQUE, alias TEXT);
CREATE TABLE crash (crash_id SERIAL PRIMARY KEY, "date" TIMESTAMP, project_name TEXT, project_ver TEXT, crash_dmp BYTEA, device_id INTEGER, textsearch TSVECTOR, dump TEXT REFERENCES device(device_id) NOT NULL);
CREATE TABLE elf_file (elf_file_id SERIAL PRIMARY KEY, "date" TIMESTAMP, project_name TEXT, project_ver TEXT, elf_file BYTEA, file_size INTEGER, project_alias TEXT);
CREATE TABLE project_auth (project_auth_id SERIAL PRIMARY KEY, "date" TIMESTAMP, project_name TEXT, github TEXT);
CREATE INDEX textsearch_idx ON crash USING GIN (textsearch);


CREATE OR REPLACE FUNCTION update_textsearch() RETURNS TRIGGER AS $$
DECLARE
    ext_device_id TEXT;
    device_alias TEXT;
    elf_file_id INTEGER;
    project_ver TEXT;
    project_alias TEXT;
BEGIN
    -- Fetch the ext_device_id and alias from the device table
    SELECT d.ext_device_id, d.alias INTO ext_device_id, device_alias
    FROM device d
    WHERE d.device_id = NEW.device_id;

    -- Fetch the project_alias from the elf_file table
    SELECT e.elf_file_id, e.project_alias, e.project_ver INTO elf_file_id, project_alias, project_ver
    FROM elf_file e
    WHERE e.project_name = NEW.project_name AND e.project_ver = NEW.project_ver;

    -- Update the textsearch column
    NEW.textsearch := to_tsvector('english',
        coalesce(NEW.date::TEXT, '') || ' ' ||
        coalesce(NEW.crash_id::TEXT, '') || ' ' ||
        coalesce(ext_device_id, '') || ' ' ||
        coalesce(device_alias, '') || ' ' ||
        coalesce(NEW.device_id::TEXT, '') || ' ' ||
        coalesce(NEW.project_name, '') || ' ' ||
        coalesce(NEW.project_ver, '') || ' ' ||
        coalesce(NEW.dump, '') || ' ' ||
        coalesce(elf_file_id::TEXT, '') || ' ' ||
        coalesce(project_alias, '') || ' ' ||
        coalesce(project_ver, ''));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER trigger_update_textsearch
BEFORE INSERT OR UPDATE ON crash
FOR EACH ROW EXECUTE FUNCTION update_textsearch();

CREATE TABLE project_webhooks (webhook_id SERIAL PRIMARY KEY, project_name TEXT, webhook_url TEXT);
CREATE TABLE project_slack_integrations (
    slack_integration_id SERIAL PRIMARY KEY,
    project_name TEXT,
    slack_team_id TEXT,
    slack_team_name TEXT,
    slack_channel_id TEXT,
    slack_channel_name TEXT,
    slack_access_token TEXT,
    created_date TIMESTAMP DEFAULT NOW(),
    github_user TEXT
);

CREATE INDEX idx_elf_file_project ON elf_file (project_name, project_ver);
CREATE INDEX idx_elf_file_project_name ON elf_file (project_name);