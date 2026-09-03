"""Short-lived signed tickets authorising one interactive debug session.

The debug service runs in its own container and the browser reaches it over a
WebSocket, so it needs to know who is connecting and which crash they asked
for. Neither of the obvious options works: a browser cannot set headers on a
WebSocket handshake, and sharing the web app's session cookie would mean
sharing `APP_SECRET_KEY` across a second process and constraining both to one
origin.

So the web app - where the GitHub session and the project ACLs already live -
mints a ticket naming the user and the crash, and the browser passes it in the
WebSocket URL. The ticket is deliberately *not* the authorisation: the debug
service re-checks the user's access against the database before starting
anything. A ticket is a short-lived statement of "this request came from our
web app on behalf of this user", which means a leaked signing key alone grants
nothing, and an ACL revoked a second ago takes effect immediately.

Kept free of Flask so both processes can share it (each supplies the secret
from its own config) and so it can be unit-tested without an app context.
"""
import secrets

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

# A ticket is redeemed within a couple of seconds of being issued - the browser
# fetches one and immediately opens the socket - so the window only needs to
# cover a slow page load, not a user's think time.
DEFAULT_TTL_SECONDS = 60

_SALT = "esp-crash-gdb-session"


class InvalidTicket(Exception):
    """Signature failed, ticket expired, payload malformed, or already used.

    One exception for all of these on purpose: the client can do nothing
    differently in each case (ask the web app for a fresh ticket), and
    distinguishing them in a response would tell an attacker which half of a
    guess was right.
    """


class TicketSigner:
    def __init__(self, secret, ttl_seconds=DEFAULT_TTL_SECONDS):
        if not secret:
            raise ValueError("a ticket signing secret is required")
        self._s = URLSafeTimedSerializer(secret, salt=_SALT)
        self.ttl_seconds = ttl_seconds

    def issue(self, gh_user, crash_id):
        """Mint a ticket for `gh_user` to debug `crash_id`.

        `jti` makes the ticket single-use: without it, two tabs (or an attacker
        who observed the URL) could redeem the same ticket repeatedly for as
        long as it remained unexpired.
        """
        return self._s.dumps({
            "u": gh_user,
            "c": int(crash_id),
            "jti": secrets.token_urlsafe(12),
        })

    def verify(self, token):
        """Return `(gh_user, crash_id, jti)` or raise InvalidTicket."""
        if not token:
            raise InvalidTicket("no ticket supplied")
        try:
            data = self._s.loads(token, max_age=self.ttl_seconds)
        except SignatureExpired:
            raise InvalidTicket("ticket expired") from None
        except BadSignature:
            raise InvalidTicket("bad ticket signature") from None
        try:
            gh_user, crash_id, jti = data["u"], int(data["c"]), data["jti"]
        except (KeyError, TypeError, ValueError):
            raise InvalidTicket("malformed ticket payload") from None
        if not gh_user or not jti:
            raise InvalidTicket("malformed ticket payload")
        return gh_user, crash_id, jti


class ReplayGuard:
    """Remembers redeemed ticket ids so none can be used twice.

    Process-local, like the MCP server's in-memory auth-code store, and
    acceptable for the same reason: a restart only means outstanding tickets
    must be re-issued, which the browser does automatically. Bounded so a flood
    of connection attempts cannot grow it without limit - and it only ever
    needs to hold ids that are still within the signing TTL, so eviction of the
    oldest entry can never let a *live* ticket be replayed unless far more
    tickets than `maxsize` were issued inside that TTL.
    """

    def __init__(self, maxsize=4096):
        self.maxsize = maxsize
        self._seen = {}

    def consume(self, jti):
        """Claim `jti`. Raises InvalidTicket if it was already claimed."""
        if jti in self._seen:
            raise InvalidTicket("ticket already used")
        self._seen[jti] = None
        while len(self._seen) > self.maxsize:
            self._seen.pop(next(iter(self._seen)))
