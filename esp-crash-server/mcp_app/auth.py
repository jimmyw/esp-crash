"""GitHub-backed OAuth 2.1 authorization-server provider for the MCP server.

Implements the MCP SDK's OAuthAuthorizationServerProvider protocol so a single
FastMCP process acts as both the Authorization Server (issuing tokens to MCP
clients) and, via ProviderTokenVerifier, the Resource Server. User login is
delegated upstream to GitHub - reusing the same GitHub OAuth app the web UI
uses - and the resulting GitHub username is stored as the token's `subject`,
which the tools read to enforce per-user ACLs.

The SDK's token handler verifies PKCE (S256) and redirect_uri consistency
before calling exchange_authorization_code, so this provider does not repeat
that. Client/code/token stores are in-memory: fine for v1, but tokens reset on
process restart (clients must re-authenticate) - persisting them (e.g. a DB
table) is a deliberate follow-up.
"""
import secrets
import time
from urllib.parse import urlencode

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

_ACCESS_TOKEN_TTL = 3600  # seconds
_AUTH_CODE_TTL = 600  # seconds


class GitHubOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    def __init__(
        self, github_client_id, github_client_secret, callback_url, mcp_scope="esp-crash",
        service_token=None, service_github_user=None,
    ):
        self.github_client_id = github_client_id
        self.github_client_secret = github_client_secret
        self.callback_url = callback_url  # {MCP_PUBLIC_URL}/github/callback
        self.mcp_scope = mcp_scope
        # Optional non-interactive path for trusted automation (e.g. the cron
        # worker's Claude-driven summarize/tag call) - a static shared secret
        # standing in for a browser-driven GitHub login. subject is just a
        # project_auth.github string like any other; it's never validated
        # against a real GitHub account, so the caller must be explicitly
        # granted project_auth access like any other user.
        self.service_token = service_token
        self.service_github_user = service_github_user

        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        # upstream-flow state -> (mcp_client_id, original AuthorizationParams)
        self._pending: dict[str, tuple[str, AuthorizationParams]] = {}

    # ---- dynamic client registration --------------------------------------

    async def get_client(self, client_id):
        return self.clients.get(client_id)

    async def register_client(self, client_info):
        self.clients[client_info.client_id] = client_info

    # ---- authorize: delegate to GitHub ------------------------------------

    async def authorize(self, client, params):
        state = secrets.token_urlsafe(32)
        self._pending[state] = (client.client_id, params)
        query = urlencode(
            {
                "client_id": self.github_client_id,
                "redirect_uri": self.callback_url,
                "scope": "read:user",
                "state": state,
            }
        )
        return f"{GITHUB_AUTHORIZE_URL}?{query}"

    async def handle_github_callback(self, request: Request) -> RedirectResponse | JSONResponse:
        """Custom route: GitHub redirects here after login. Exchange the code
        for the GitHub username, mint an MCP authorization code bound to it,
        and redirect back to the MCP client's redirect_uri."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state or state not in self._pending:
            return JSONResponse({"error": "invalid_state"}, status_code=400)
        client_id, params = self._pending.pop(state)

        async with httpx.AsyncClient(timeout=10) as http:
            token_resp = await http.post(
                GITHUB_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.github_client_id,
                    "client_secret": self.github_client_secret,
                    "code": code,
                    "redirect_uri": self.callback_url,
                },
            )
            gh_token = token_resp.json().get("access_token")
            if not gh_token:
                return JSONResponse({"error": "github_token_exchange_failed"}, status_code=400)
            user_resp = await http.get(
                GITHUB_USER_URL,
                headers={"Authorization": f"Bearer {gh_token}", "Accept": "application/json"},
            )
            login = user_resp.json().get("login")
        if not login:
            return JSONResponse({"error": "github_user_lookup_failed"}, status_code=400)

        mcp_code = secrets.token_urlsafe(32)
        self.auth_codes[mcp_code] = AuthorizationCode(
            code=mcp_code,
            scopes=params.scopes or [self.mcp_scope],
            expires_at=time.time() + _AUTH_CODE_TTL,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=login,  # <- GitHub identity flows through to the AccessToken
        )
        redirect_to = construct_redirect_uri(str(params.redirect_uri), code=mcp_code, state=params.state)
        return RedirectResponse(url=redirect_to, status_code=302)

    # ---- authorization code -> tokens (PKCE already checked by SDK) --------

    async def load_authorization_code(self, client, authorization_code):
        code = self.auth_codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            self.auth_codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(self, client, authorization_code):
        self.auth_codes.pop(authorization_code.code, None)
        return self._issue_tokens(
            client.client_id, authorization_code.scopes, authorization_code.subject
        )

    # ---- refresh -----------------------------------------------------------

    async def load_refresh_token(self, client, refresh_token):
        rt = self.refresh_tokens.get(refresh_token)
        if rt is None or rt.client_id != client.client_id:
            return None
        return rt

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        self.refresh_tokens.pop(refresh_token.token, None)
        return self._issue_tokens(
            client.client_id, scopes or refresh_token.scopes, refresh_token.subject
        )

    # ---- resource-server side ---------------------------------------------

    async def load_access_token(self, token):
        if self.service_token and token == self.service_token:
            return AccessToken(
                token=token, client_id="service", scopes=[self.mcp_scope],
                expires_at=None, subject=self.service_github_user,
            )
        at = self.access_tokens.get(token)
        if at is None:
            return None
        if at.expires_at is not None and at.expires_at < time.time():
            self.access_tokens.pop(token, None)
            return None
        return at

    async def revoke_token(self, token):
        # token is an AccessToken or RefreshToken; drop from whichever store.
        self.access_tokens.pop(token.token, None)
        self.refresh_tokens.pop(token.token, None)

    # ---- helpers -----------------------------------------------------------

    def _issue_tokens(self, client_id, scopes, subject) -> OAuthToken:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = int(time.time())
        self.access_tokens[access] = AccessToken(
            token=access, client_id=client_id, scopes=scopes,
            expires_at=now + _ACCESS_TOKEN_TTL, subject=subject,
        )
        self.refresh_tokens[refresh] = RefreshToken(
            token=refresh, client_id=client_id, scopes=scopes, subject=subject,
        )
        return OAuthToken(
            access_token=access, token_type="Bearer", expires_in=_ACCESS_TOKEN_TTL,
            scope=" ".join(scopes), refresh_token=refresh,
        )
