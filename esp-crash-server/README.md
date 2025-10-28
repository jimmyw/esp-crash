# ESP-Crash Server part

This is the service that runs on https://esp-crash.wennlund.nu/

You are free to use this service free of charge, for simple easy access, but for these that like
to set up their own instance, you are free to do so.

Use the provided Dockerfile to host the server part, and you need to configure git credentials and sql server yourself.

## Slack Integration

ESP-Crash now supports native Slack integration for crash notifications with rich formatting and interactive elements.

### Slack Advantages
- Professional formatted messages
- Action buttons for quick access
- Channel-specific routing
- Team-based token management
- **Auto-join capability**: Bot automatically joins public channels when needed
- No additional webhook configuration needed

### Setup for Self-Hosted Instances

1. **Create a Slack App**:
   - Go to https://api.slack.com/apps
   - Click "Create New App" → "From scratch"
   - Name your app (e.g., "ESP-Crash") and select your workspace
   - Note down your App ID and Client ID

2. **Configure OAuth & Permissions**:
   - Go to "OAuth & Permissions" in your app settings
   - Add your redirect URI: `https://your-domain.com/slack/callback`
   - Add the following Bot Token Scopes:
     - `chat:write` - Send messages to channels
     - `channels:read` - View basic information about public channels
     - `groups:read` - View basic information about private channels
     - `channels:join` - Join public channels automatically

3. **Environment Variables**:
   ```bash
   SLACK_CLIENT_ID=your_client_id_here
   SLACK_CLIENT_SECRET=your_client_secret_here
   ```

4. **Database Migration**:
   Run the migration script to add Slack tables:
   ```bash
   psql -d your_database -f slack_migration.sql
   ```

5. **Install Dependencies**:
   ```bash
   pip install slack-sdk
   ```

### Usage

1. Navigate to your project settings page
2. Click "Add to Slack" in the Slack Integration section
3. Authorize the app for your Slack workspace
4. Select which workspace and channel should receive crash notifications
5. Complete the integration setup
6. Crash notifications will now be sent to Slack with rich formatting

### Message Format

Slack notifications include:
- **Header**: "🚨 ESP Crash Detected"
- **Project Details**: Name, version, crash ID
- **Crash Dump**: First 500 characters of the crash dump
- **Action Button**: Direct link to view full crash details

### Webhook vs Slack Integration

- **Webhooks**: Generic JSON payload, works with any service
- **Slack Integration**: Native Slack formatting with interactive elements, OAuth-based authentication