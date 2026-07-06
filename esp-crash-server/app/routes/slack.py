"""Slack OAuth, interactivity, channel selection/management, test, and
verify. Mechanical move from server.py - routes and logic unchanged,
endpoint names preserved exactly (registered directly on the app object,
not via Flask Blueprint - see core.py for why).

`slack_sdk` and `requests` are imported as modules here (not `from x import
y`) and accessed via dotted attribute at each call site, so monkeypatching
`slack_sdk.WebClient` or `requests.post` affects every route module that
uses them from a single patch point, instead of each module's own frozen
`from slack_sdk import WebClient`-style local binding."""
import datetime
import json

import requests
import slack_sdk
from flask import current_app, redirect, request, session, url_for
from slack_sdk.errors import SlackApiError
from sqlalchemy import delete, insert, select, update

from ..auth import auth_filter, auth_project_in_filter, login_required
from ..models import ProjectAuth, ProjectSlackIntegration, db
from ..rendering import external_url_for, render_template


@login_required
def slack_auth(project_name):
    """Initiate Slack OAuth flow for a project."""
    # Permission check: Ensure user is authorized for this project
    auth_check = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    # Store project_name in session for callback
    session['slack_auth_project'] = project_name

    # Redirect to Slack OAuth
    slack_oauth_url = (
        f"https://slack.com/oauth/v2/authorize?"
        f"client_id={current_app.config['SLACK_CLIENT_ID']}&"
        f"scope=chat:write,channels:read,groups:read,channels:join&"
        f"redirect_uri={url_for('slack_callback', _external=True)}"
    )
    return redirect(slack_oauth_url)


@login_required
def slack_callback():
    """Handle Slack OAuth callback."""
    code = request.args.get('code')
    error = request.args.get('error')

    if error:
        return f"Slack authorization failed: {error}", 400

    if not code:
        return "Missing authorization code from Slack", 400

    project_name = session.get('slack_auth_project')
    if not project_name:
        return "Missing project information. Please try again.", 400

    try:
        # Exchange code for access token
        response = requests.post('https://slack.com/api/oauth.v2.access', data={
            'client_id': current_app.config['SLACK_CLIENT_ID'],
            'client_secret': current_app.config['SLACK_CLIENT_SECRET'],
            'code': code,
            'redirect_uri': url_for('slack_callback', _external=True)
        })

        slack_response = response.json()

        if not slack_response.get('ok'):
            return f"Slack API error: {slack_response.get('error', 'Unknown error')}", 400

        access_token = slack_response['access_token']
        team_id = slack_response['team']['id']
        team_name = slack_response['team']['name']

        # Store OAuth data in session for channel selection
        session['slack_oauth_data'] = {
            'access_token': access_token,
            'team_id': team_id,
            'team_name': team_name,
            'project_name': project_name
        }

        # Redirect to channel selection page
        return redirect(url_for('slack_channel_selection', project_name=project_name))

    except Exception as e:
        current_app.logger.error(f"Slack OAuth error: {e}")
        return f"Failed to complete Slack integration: {str(e)}", 500


def handle_slack_interactivity():
    """Handle Slack interactive component events."""
    try:
        # Slack sends the payload as form data
        payload = json.loads(request.form.get('payload', '{}'))

        # Log the interaction for debugging
        current_app.logger.info(f"Slack interaction received: {payload.get('type', 'unknown')}")

        if payload.get('type') == 'block_actions':
            # Handle button clicks
            action = payload['actions'][0] if payload.get('actions') else {}
            action_id = action.get('action_id', '')

            current_app.logger.info(f"Button clicked: {action_id}")

            # For URL buttons, just return empty response and let Slack handle the URL redirect
            if action_id in ['view_crash_details', 'view_project_settings']:
                # Return empty 200 response - this tells Slack to proceed with the URL
                return '', 200

        # For any other interaction types, just acknowledge
        return '', 200

    except Exception as e:
        current_app.logger.error(f"Slack interactivity error: {e}")
        # Always return 200 to avoid Slack retries
        return '', 200


@login_required
def slack_channel_selection(project_name):
    """Show channel selection page after successful OAuth."""
    oauth_data = session.get('slack_oauth_data')
    if not oauth_data or oauth_data.get('project_name') != project_name:
        return "Session expired or invalid. Please try adding Slack integration again.", 400

    # Permission check
    auth_check = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    try:
        slack_client = slack_sdk.WebClient(token=oauth_data['access_token'])

        # Get public channels
        channels_response = slack_client.conversations_list(
            types="public_channel,private_channel",
            exclude_archived=True,
            limit=200
        )

        if not channels_response['ok']:
            return f"Failed to fetch channels: {channels_response.get('error', 'Unknown error')}", 400

        channels = []
        for channel in channels_response['channels']:
            if channel.get('is_member', False) or not channel.get('is_private', False):
                channels.append({
                    'id': channel['id'],
                    'name': channel['name'],
                    'is_private': channel.get('is_private', False),
                    'purpose': channel.get('purpose', {}).get('value', '')[:100]
                })

        # Sort channels by name
        channels.sort(key=lambda x: x['name'])

        return render_template('slack_channel_selection.html',
                             project_name=project_name,
                             team_name=oauth_data['team_name'],
                             channels=channels)

    except Exception as e:
        current_app.logger.error(f"Channel selection error: {e}")
        return f"Failed to load channels: {str(e)}", 500


@login_required
def slack_channel_selection_post(project_name):
    """Process channel selection and save integration."""
    oauth_data = session.get('slack_oauth_data')
    if not oauth_data or oauth_data.get('project_name') != project_name:
        return "Session expired or invalid. Please try adding Slack integration again.", 400

    selected_channel_id = request.form.get('channel_id')
    selected_channel_name = request.form.get('channel_name')

    if not selected_channel_id or not selected_channel_name:
        return "Please select a channel.", 400

    try:
        # Check if integration already exists for this team
        existing = db.session.execute(
            select(ProjectSlackIntegration.slack_integration_id)
            .where(
                ProjectSlackIntegration.project_name == project_name,
                ProjectSlackIntegration.slack_team_id == oauth_data['team_id'],
            )
        ).mappings().all()

        if existing:
            # Update existing integration
            db.session.execute(
                update(ProjectSlackIntegration)
                .where(
                    ProjectSlackIntegration.project_name == project_name,
                    ProjectSlackIntegration.slack_team_id == oauth_data['team_id'],
                )
                .values(
                    slack_access_token=oauth_data['access_token'],
                    slack_team_name=oauth_data['team_name'],
                    slack_channel_id=selected_channel_id,
                    slack_channel_name=selected_channel_name,
                )
            )
        else:
            # Create new integration
            db.session.execute(
                insert(ProjectSlackIntegration).values(
                    project_name=project_name,
                    slack_team_id=oauth_data['team_id'],
                    slack_team_name=oauth_data['team_name'],
                    slack_channel_id=selected_channel_id,
                    slack_channel_name=selected_channel_name,
                    slack_access_token=oauth_data['access_token'],
                    github_user=session.get("gh_user"),
                )
            )

        db.session.commit()

        # Clean up session
        session.pop('slack_oauth_data', None)
        session.pop('slack_auth_project', None)

        return redirect(url_for('project_settings', project_name=project_name))

    except Exception as e:
        current_app.logger.error(f"Failed to save Slack integration: {e}")
        return f"Failed to save integration: {str(e)}", 500


@login_required
def delete_slack_integration(project_name, integration_id):
    """Delete a Slack integration."""
    # Permission check and delete. Scope to the caller's projects via a
    # project_auth membership subquery (no-op TRUE in no-auth mode). The
    # original spliced a bare `github` column onto this table, which has none -
    # a no-op under no-auth but a 500 under github auth.
    db.session.execute(
        delete(ProjectSlackIntegration).where(
            ProjectSlackIntegration.slack_integration_id == integration_id,
            ProjectSlackIntegration.project_name == project_name,
            auth_project_in_filter(ProjectSlackIntegration.project_name),
        )
    )
    db.session.commit()
    return redirect(url_for('project_settings', project_name=project_name))


@login_required
def update_slack_channel(project_name, integration_id):
    """Update Slack channel for an integration."""
    channel_id = request.form.get('channel_id')
    channel_name = request.form.get('channel_name')

    if not channel_id or not channel_name:
        return "Missing channel information", 400

    # Update channel information. Same project-membership scoping as
    # delete_slack_integration (see there).
    db.session.execute(
        update(ProjectSlackIntegration)
        .where(
            ProjectSlackIntegration.slack_integration_id == integration_id,
            ProjectSlackIntegration.project_name == project_name,
            auth_project_in_filter(ProjectSlackIntegration.project_name),
        )
        .values(slack_channel_id=channel_id, slack_channel_name=channel_name)
    )
    db.session.commit()
    return redirect(url_for('project_settings', project_name=project_name))


@login_required
def test_slack_integration(project_name):
    """Test Slack integration by sending a test message."""
    # Permission check
    auth_check = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    # Get Slack integrations
    slack_integrations = db.session.execute(
        select(
            ProjectSlackIntegration.slack_access_token, ProjectSlackIntegration.slack_channel_id,
            ProjectSlackIntegration.slack_channel_name, ProjectSlackIntegration.slack_team_id,
            ProjectSlackIntegration.slack_team_name,
        ).where(ProjectSlackIntegration.project_name == project_name)
    ).mappings().all()

    if not slack_integrations:
        return "No Slack integrations found for this project.", 404

    results = []
    debug_info = []
    test_url = external_url_for('project_settings', project_name=project_name)

    current_app.logger.info(f"Generated test URL: {test_url}")

    for integration in slack_integrations:
        channel_name = integration['slack_channel_name']
        channel_id = integration['slack_channel_id']
        team_name = integration.get('slack_team_name', 'Unknown')

        debug_info.append(f"Testing integration for team: {team_name}, channel: #{channel_name} (ID: {channel_id})")

        try:
            slack_client = slack_sdk.WebClient(token=integration["slack_access_token"])

            # First, let's check if we can access channel info
            try:
                channel_info = slack_client.conversations_info(channel=channel_id)
                if channel_info["ok"]:
                    debug_info.append(f"✅ Channel info retrieved successfully for #{channel_name}")
                    debug_info.append(f"   - Channel exists: {channel_info['channel']['name']}")
                    debug_info.append(f"   - Is member: {channel_info['channel'].get('is_member', 'Unknown')}")
                else:
                    debug_info.append(f"❌ Failed to get channel info: {channel_info.get('error', 'Unknown error')}")
            except Exception as info_error:
                debug_info.append(f"❌ Error getting channel info: {info_error}")

            # Now try to send the message
            debug_info.append(f"Attempting to send message to #{channel_name}...")

            response = slack_client.chat_postMessage(
                channel=channel_id,
                blocks=[
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 ESP-Crash Test Message"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"This is a test message from ESP-Crash for project *{project_name}*.\n\nIf you see this message, the Slack integration is working correctly!\n\n*Debug Info:*\n• Team: {team_name}\n• Channel: #{channel_name}\n• Channel ID: {channel_id}\n• Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Project Settings"
                                },
                                "url": test_url,
                                "action_id": "view_project_settings"
                            }
                        ]
                    }
                ],
                text=f"ESP-Crash test message for {project_name}"
            )

            # Log the full response for debugging
            debug_info.append(f"Slack API Response: {response}")

            if response["ok"]:
                message_ts = response.get('ts', 'Unknown')
                workspace_name = integration.get('slack_team_name', 'Unknown')
                results.append(f"✅ Successfully sent test message to #{channel_name} in '{workspace_name}' workspace (message timestamp: {message_ts})")
                debug_info.append(f"✅ Message sent successfully with timestamp: {message_ts}")
            else:
                error_msg = response.get('error', 'Unknown error')
                if error_msg == 'not_in_channel':
                    # Try to join the channel automatically (only works for public channels)
                    try:
                        join_response = slack_client.conversations_join(channel=integration["slack_channel_id"])
                        if join_response["ok"]:
                            # Successfully joined, now try to send the message again
                            retry_response = slack_client.chat_postMessage(
                                channel=integration["slack_channel_id"],
                                blocks=[
                                    {
                                        "type": "header",
                                        "text": {
                                            "type": "plain_text",
                                            "text": "🧪 ESP-Crash Test Message"
                                        }
                                    },
                                    {
                                        "type": "section",
                                        "text": {
                                            "type": "mrkdwn",
                                            "text": f"This is a test message from ESP-Crash for project *{project_name}*.\n\nThe bot automatically joined this channel and sent this test message!"
                                        }
                                    },
                                    {
                                        "type": "actions",
                                        "elements": [
                                            {
                                                "type": "button",
                                                "text": {
                                                    "type": "plain_text",
                                                    "text": "Project Settings"
                                                },
                                                "url": test_url,
                                                "action_id": "view_project_settings"
                                            }
                                        ]
                                    }
                                ],
                                text=f"ESP-Crash test message for {project_name}"
                            )
                            if retry_response["ok"]:
                                results.append(f"✅ Auto-joined #{integration['slack_channel_name']} and sent test message successfully")
                            else:
                                results.append(f"⚠️ Joined #{integration['slack_channel_name']} but failed to send message: {retry_response.get('error', 'Unknown error')}")
                        else:
                            # Could not join (probably a private channel)
                            results.append(f"❌ Bot not in channel #{integration['slack_channel_name']}: Please invite the ESP-Crash bot to this channel first. Go to the channel and type: <code>/invite @ESP-Crash</code>")
                    except Exception as join_error:
                        results.append(f"❌ Bot not in channel #{integration['slack_channel_name']}: Could not auto-join. Please invite the bot manually: <code>/invite @ESP-Crash</code>")
                elif error_msg == 'channel_not_found':
                    results.append(f"❌ Channel #{integration['slack_channel_name']} not found: The channel may have been deleted or renamed")
                elif error_msg == 'invalid_auth' or error_msg == 'token_revoked':
                    results.append(f"❌ Authentication failed for #{integration['slack_channel_name']}: Please reconnect the Slack integration")
                else:
                    results.append(f"❌ Failed to send to #{integration['slack_channel_name']}: {error_msg}")

        except SlackApiError as e:
            error_msg = str(e)
            if 'not_in_channel' in error_msg:
                results.append(f"❌ Bot not in channel #{integration['slack_channel_name']}: Please invite the ESP-Crash bot to this channel first. Go to the channel and type: <code>/invite @ESP-Crash</code>")
            elif 'channel_not_found' in error_msg:
                results.append(f"❌ Channel #{integration['slack_channel_name']} not found: The channel may have been deleted or renamed")
            elif 'invalid_auth' in error_msg or 'token_revoked' in error_msg:
                results.append(f"❌ Authentication failed for #{integration['slack_channel_name']}: Please reconnect the Slack integration")
            else:
                results.append(f"❌ Slack API error for #{integration['slack_channel_name']}: {e}")
        except Exception as e:
            results.append(f"❌ Unexpected error for #{integration['slack_channel_name']}: {e}")

    # Check for success and "not_in_channel" patterns
    has_success = any('✅' in result for result in results)
    has_not_in_channel = any('not_in_channel' in result for result in results)

    return render_template('slack_test_results.html',
                           project_name=project_name,
                           results=results,
                           debug_info=debug_info,
                           has_success=has_success,
                           has_not_in_channel=has_not_in_channel)


@login_required
def verify_slack_integration(project_name):
    """Verify Slack integration settings and permissions."""
    # Permission check
    auth_check = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    # Get Slack integrations with enhanced info
    slack_integrations = db.session.execute(
        select(
            ProjectSlackIntegration.slack_integration_id, ProjectSlackIntegration.slack_access_token,
            ProjectSlackIntegration.slack_channel_id, ProjectSlackIntegration.slack_channel_name,
            ProjectSlackIntegration.slack_team_name, ProjectSlackIntegration.slack_team_id,
        ).where(ProjectSlackIntegration.project_name == project_name)
    ).mappings().all()

    if not slack_integrations:
        return render_template('slack_verification.html',
                               project_name=project_name,
                               integrations=[],
                               verification_results=["No Slack integrations found for this project."])

    verification_results = []
    db_info = []

    # Prepare integration data with validation status
    integrations_with_status = []

    for integration in slack_integrations:
        integration_data = {
            'id': integration['slack_integration_id'],
            'team_name': integration.get('slack_team_name', 'Unknown Team'),
            'channel_name': integration['slack_channel_name'],
            'channel_id': integration['slack_channel_id'],
            'bot_valid': False
        }

        verification_results.append(f"Verifying integration for {integration.get('slack_team_name', 'Unknown Team')}")

        try:
            slack_client = slack_sdk.WebClient(token=integration["slack_access_token"])

            # Test auth
            auth_test = slack_client.auth_test()
            if auth_test["ok"]:
                integration_data['bot_valid'] = True
                verification_results.append(f"✅ Auth test passed")
                verification_results.append(f"   Bot User ID: {auth_test.get('user_id', 'Unknown')}")
                verification_results.append(f"   Team: {auth_test.get('team', 'Unknown')}")
                verification_results.append(f"   User: {auth_test.get('user', 'Unknown')}")

                db_info.append(f"Integration ID: {integration['slack_integration_id']}")
                db_info.append(f"Team ID: {integration.get('slack_team_id', 'Unknown')}")
                db_info.append(f"Channel ID: {integration['slack_channel_id']}")
                db_info.append(f"Token: {integration['slack_access_token'][:10]}...")
            else:
                verification_results.append(f"❌ Auth test failed: {auth_test.get('error', 'Unknown')}")
                continue

            # Check channel info
            channel_info = slack_client.conversations_info(channel=integration["slack_channel_id"])
            if channel_info["ok"]:
                channel = channel_info["channel"]
                verification_results.append(f"✅ Channel info retrieved")
                verification_results.append(f"   Channel Name: #{channel.get('name', 'Unknown')}")
                verification_results.append(f"   Channel ID: {channel.get('id', 'Unknown')}")
                verification_results.append(f"   Is Member: {channel.get('is_member', False)}")
                verification_results.append(f"   Is Private: {channel.get('is_private', False)}")
                verification_results.append(f"   Is Archived: {channel.get('is_archived', False)}")
            else:
                verification_results.append(f"❌ Channel info failed: {channel_info.get('error', 'Unknown')}")

        except Exception as e:
            verification_results.append(f"❌ Verification error: {e}")

        integrations_with_status.append(integration_data)

    return render_template('slack_verification.html',
                           project_name=project_name,
                           integrations=integrations_with_status,
                           verification_results=verification_results,
                           db_info=db_info)


def register(app):
    app.add_url_rule('/projects/<project_name>/slack/auth', endpoint="slack_auth", view_func=slack_auth)
    app.add_url_rule('/slack/callback', endpoint="slack_callback", view_func=slack_callback)
    app.add_url_rule('/slack/interactive', endpoint="handle_slack_interactivity", view_func=handle_slack_interactivity, methods=['POST'])
    app.add_url_rule('/projects/<project_name>/slack/channel-selection', endpoint="slack_channel_selection", view_func=slack_channel_selection)
    app.add_url_rule('/projects/<project_name>/slack/channel-selection', endpoint="slack_channel_selection_post", view_func=slack_channel_selection_post, methods=['POST'])
    app.add_url_rule('/projects/<project_name>/slack/<int:integration_id>/delete', endpoint="delete_slack_integration", view_func=delete_slack_integration)
    app.add_url_rule('/projects/<project_name>/slack/<int:integration_id>/update_channel', endpoint="update_slack_channel", view_func=update_slack_channel, methods=['POST'])
    app.add_url_rule('/projects/<project_name>/slack/test', endpoint="test_slack_integration", view_func=test_slack_integration)
    app.add_url_rule('/projects/<project_name>/slack/verify', endpoint="verify_slack_integration", view_func=verify_slack_integration)
