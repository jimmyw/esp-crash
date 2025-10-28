-- Migration script to add Slack integration support
-- Run this script to add Slack functionality to existing ESP-Crash installations

CREATE TABLE IF NOT EXISTS project_slack_integrations (
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

-- Add team_name column if table already exists
ALTER TABLE project_slack_integrations ADD COLUMN IF NOT EXISTS slack_team_name TEXT;

-- Add index for efficient lookups
CREATE INDEX IF NOT EXISTS idx_project_slack_integrations_project 
ON project_slack_integrations(project_name);

-- Add index for team lookups
CREATE INDEX IF NOT EXISTS idx_project_slack_integrations_team 
ON project_slack_integrations(slack_team_id);