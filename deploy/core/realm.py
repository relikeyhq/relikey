# SPDX-License-Identifier: EUPL-1.2
"""Set up the core broker's realm for ReliKey and KeyClerk (decisions 0010, 0015; KeyClerk decisions 0003, 0007).

Runs inside the core pod (the `setup` service in compose.yaml, started by install.py), against Keycloak on the pod's
loopback with the bootstrap admin. Standard library only, so it runs in the KeyClerk image. Every step can run again.

- the realm with SCIM on, brute-force protection, a password policy, user and admin events, short access tokens;
- the user profile: e-mail editable by admins only (the identity key Warpgate matches, 0010) and an admin-only
  "anchor" attribute behind SCIM externalId, so people are found by an immutable id while usernames stay human;
- KeyClerk's writer (group membership only, through fine-grained admin permissions, SCIM audience) and reader
  (views users and groups, reads memberships), confidential, full scope off, secrets from install.py;
- the desk's public client (PKCE S256, the anchor and the keyclerk-viewer role in its tokens, back-channel logout to
  the desk on loopback);
- one client policy for every client: PKCE, no implicit grant, no password grant, no front-channel logout;
- the first people (the root holder and the officer), each with their anchor, a temporary password and a passkey to
  register at the first sign-in;
- with `edge`, one edge's Warpgate client: confidential, PKCE S256, its one return URL (decision 0010: the broker
  authenticates, the agent provisions; Warpgate's provider maps no roles). The secret comes on stdin, never printed.
- with `vendor`, a vendor's own OpenID provider (decision 0018): a vendor's person signs in there, but only an identity
  already linked to a provisioned person by the provider's subject gets in (an unlinked one is denied, never matched by
  e-mail or created), nothing is imported from the provider, and the person's ReliKey passkey is still required after.
  `vendor-link` links one person to their subject at that provider.

    python realm.py <people.json>     (env: REALM, BROKER_URL, DESK_URL, KC_BOOTSTRAP_ADMIN_USERNAME/_PASSWORD)
    python realm.py edge <edge> <Warpgate's external URL> < secret
    python realm.py vendor <alias> <issuer URL> <client id> "<display name>" < secret
    python realm.py vendor-link <username> <alias> <subject>
    python realm.py fleet <the fleet page's URL> < secret
    python realm.py fleet-grant|fleet-revoke <username>
    python realm.py setup-client      (an existing realm: add the setup client, as the bootstrap admin)

Who signs in (stack attack 2026-10-25, C1): the full setup, setup-client, passkey, vendor-link and fleet-grant act as
the bootstrap admin (the realm's flows and its people); edge, vendor and fleet act as the realm's own setup client
(relikey-setup: clients and identity providers in this realm only, nothing over people, login flows or the master
realm), so the bootstrap admin can be removed once the realm is set up.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

KC = os.environ.get("KC_URL", "http://127.0.0.1:8080")   # the broker on the pod's loopback (tests point elsewhere)
REALM = os.environ["REALM"]
BROKER_URL = os.environ["BROKER_URL"].rstrip("/")
DESK_URL = os.environ["DESK_URL"].rstrip("/")
A = f"{KC}/admin/realms"
R = f"{A}/{REALM}"
SETUP_CLIENT, SETUP_SECRET = "relikey-setup", "/run/secrets/setup"
# Clients and identity providers, and reading the realm: what adding an edge, a vendor or the fleet page needs. Not
# manage-users (a temporary password and a passkey-registration action would take over a person), not manage-realm
# (login flows, client policies).
SETUP_ROLES = ("manage-clients", "view-clients", "manage-identity-providers", "view-identity-providers", "view-realm")
SERVICE_CLIENTS = {   # client: (realm-management roles, SCIM audience, secret file)
    "keyclerk-writer": (("view-users", "query-users", "query-groups"), True, "/run/secrets/writer"),
    "keyclerk-reader": (("view-users", "query-users", "query-groups", "view-events"), False, "/run/secrets/reader"),
}
_token = {"value": "", "at": 0.0}


def req(method, url, body=None, form=None, ok=(200, 201, 204), auth=True):
    data = urllib.parse.urlencode(form).encode() if form else (json.dumps(body).encode() if body is not None else None)
    h = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json", "Accept": "application/json"}
    if auth:
        h["Authorization"] = "Bearer " + token()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method=method, data=data, headers=h), timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else None)
    except urllib.error.HTTPError as e:
        if e.code in ok:
            return e.code, None
        raise SystemExit(f"realm setup: {method} {url.replace(KC, '')}: {e.code} {e.read()[:300]!r}") from None


def token() -> str:
    if time.time() - _token["at"] > 30:          # admin tokens live 60 s
        if _token.get("as") == "setup":           # the realm's own setup client: this realm only
            _, body = req("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", auth=False,
                          form={"grant_type": "client_credentials", "client_id": SETUP_CLIENT,
                                "client_secret": Path(SETUP_SECRET).read_text(encoding="utf-8").strip()})
            _token.update(value=body["access_token"], at=time.time())
            return _token["value"]
        if not os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD"):
            raise SystemExit("realm setup: this step acts as the bootstrap admin, which is removed (deploy/core/README.md); "
                             "do it in the broker's admin console as your permanent admin")
        _, body = req("POST", f"{KC}/realms/master/protocol/openid-connect/token", auth=False,
                      form={"grant_type": "password", "client_id": "admin-cli",
                            "username": os.environ["KC_BOOTSTRAP_ADMIN_USERNAME"],
                            "password": os.environ["KC_BOOTSTRAP_ADMIN_PASSWORD"]})
        _token.update(value=body["access_token"], at=time.time())
    return _token["value"]


def wait_for_broker(timeout=300) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"{KC}/realms/master", timeout=5) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(3)
    raise SystemExit("realm setup: the broker did not answer on the pod's loopback, so the realm is not set up. Read "
                     "the broker's log (compose logs broker) for why it is not up, then run deploy/core/install.py "
                     "again: it keeps every secret it wrote")


def client_id(name: str) -> str:
    return req("GET", f"{R}/clients?clientId={name}")[1][0]["id"]


def mappers(cid: str) -> set:
    return {m["name"] for m in req("GET", f"{R}/clients/{cid}/protocol-mappers/models")[1]}


def ensure_client(rep: dict) -> str:
    """Create the client, or bring an existing one to this representation (its secret included)."""
    # S256 on every client, service accounts too: on a re-run the pkce-enforcer policy is already on and Keycloak
    # checks it before the conflict, so a client without it is refused (400) instead of found (409) (full-stack run 2)
    rep = {**rep, "attributes": {"pkce.code.challenge.method": "S256", **rep.get("attributes", {})}}
    if req("POST", f"{R}/clients", rep, ok=(201, 409))[0] == 409:
        cid = client_id(rep["clientId"])
        req("PUT", f"{R}/clients/{cid}", {**req("GET", f"{R}/clients/{cid}")[1], **rep})
        return cid
    return client_id(rep["clientId"])


def realm() -> None:
    req("POST", A, {"realm": REALM, "enabled": True, "scimApiEnabled": True}, ok=(201, 409))
    r = req("GET", R)[1]
    r.update({"scimApiEnabled": True, "bruteForceProtected": True, "permanentLockout": False, "failureFactor": 10,
              "maxFailureWaitSeconds": 900, "passwordPolicy": "length(14) and notUsername and notEmail and maxLength(128)",
              "eventsEnabled": True, "eventsExpiration": 2592000, "adminEventsEnabled": True,
              "adminEventsDetailsEnabled": True, "accessTokenLifespan": 300, "ssoSessionIdleTimeout": 1800,
              "ssoSessionMaxLifespan": 28800, "adminPermissionsEnabled": True, "registrationAllowed": False})
    req("PUT", R, r)
    req("PUT", f"{R}/events/config", {"eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True,
                                      "eventsListeners": ["jboss-logging"], "eventsExpiration": 2592000})
    up = req("GET", f"{R}/users/profile")[1]
    for a in up["attributes"]:
        if a["name"] == "email":
            a["permissions"] = {"view": ["admin", "user"], "edit": ["admin"]}
    if not any(a["name"] == "anchor" for a in up["attributes"]):
        up["attributes"].append({"name": "anchor", "displayName": "Anchor (immutable id from the source)",
                                 "multivalued": False, "permissions": {"view": ["admin"], "edit": ["admin"]},
                                 "annotations": {"kc.scim.schema.attribute": "externalId"}})
    up.pop("unmanagedAttributePolicy", None)     # absent means disabled: no attribute outside the profile
    req("PUT", f"{R}/users/profile", up)
    req("POST", f"{R}/roles", {"name": "keyclerk-viewer", "description": "may look at everything in KeyClerk"}, ok=(201, 409))
    for ra in req("GET", f"{R}/authentication/required-actions")[1] or []:
        if ra.get("alias") == "webauthn-register-passwordless" and not ra.get("enabled"):
            req("PUT", f"{R}/authentication/required-actions/{ra['alias']}", {**ra, "enabled": True})


def service_clients() -> None:
    rm = client_id("realm-management")
    all_roles = req("GET", f"{R}/clients/{rm}/roles")[1]
    for name, (roles, scim, secret_file) in SERVICE_CLIENTS.items():
        cid = ensure_client({"clientId": name, "enabled": True, "protocol": "openid-connect", "publicClient": False,
                             "secret": Path(secret_file).read_text(encoding="utf-8").strip(),
                             "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                             "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "fullScopeAllowed": False})
        mine = [r for r in all_roles if r["name"] in roles]
        sa = req("GET", f"{R}/clients/{cid}/service-account-user")[1]["id"]
        req("POST", f"{R}/users/{sa}/role-mappings/clients/{rm}", mine)
        req("POST", f"{R}/clients/{cid}/scope-mappings/clients/{rm}", mine)   # full scope off: these only
        have = mappers(cid)
        # SCIM takes a token only with the realm's SCIM base as its audience: as the pod reaches it, and as published
        for mname, base in ((("scim-audience-loopback", KC), ("scim-audience-public", BROKER_URL)) if scim else ()):
            if mname not in have:
                req("POST", f"{R}/clients/{cid}/protocol-mappers/models", {
                    "name": mname, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                    "config": {"included.custom.audience": f"{base}/realms/{REALM}/scim/v2", "access.token.claim": "true"}})


def setup_client() -> None:
    """The realm's setup client (stack attack 2026-10-25, C1): later steps act as it, not as the master realm's admin."""
    secret = Path(SETUP_SECRET).read_text(encoding="utf-8").strip()
    if len(secret) < 32:
        raise SystemExit("realm setup: the setup client's secret (deploy/secrets/relikey-setup.secret) is shorter "
                         "than 32 characters, so it is not the one deploy/core/install.py wrote; restore that file "
                         "from the core's backup")
    rm = client_id("realm-management")
    mine = [r for r in req("GET", f"{R}/clients/{rm}/roles")[1] if r["name"] in SETUP_ROLES]
    cid = ensure_client({"clientId": SETUP_CLIENT, "enabled": True, "protocol": "openid-connect", "publicClient": False,
                         "secret": secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                         "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "fullScopeAllowed": False})
    sa = req("GET", f"{R}/clients/{cid}/service-account-user")[1]["id"]
    held = {r["name"] for r in req("GET", f"{R}/users/{sa}/role-mappings/clients/{rm}")[1]}
    extra = [{"id": r["id"], "name": r["name"]} for r in req("GET", f"{R}/users/{sa}/role-mappings/clients/{rm}")[1]
             if r["name"] not in SETUP_ROLES]
    if extra:                                     # only these roles, even if someone added more
        req("DELETE", f"{R}/users/{sa}/role-mappings/clients/{rm}", extra)
    if held != set(SETUP_ROLES):
        req("POST", f"{R}/users/{sa}/role-mappings/clients/{rm}", mine)
    req("POST", f"{R}/clients/{cid}/scope-mappings/clients/{rm}", mine)
    print(f"realm {REALM}: setup client {SETUP_CLIENT} ({', '.join(SETUP_ROLES)})")


def writer_permissions() -> None:
    """The writer manages group membership and KeyClerk's groups, and views users (fine-grained admin permissions v2,
    instead of manage-users): it cannot edit a person, their credentials, roles or anchor."""
    ap = client_id("admin-permissions")
    Z = f"{R}/clients/{ap}/authz/resource-server"
    req("POST", f"{Z}/policy/client", {"name": "keyclerk-writer", "clients": [client_id("keyclerk-writer")],
                                       "logic": "POSITIVE"}, ok=(201, 409))
    pol = [x for x in req("GET", f"{Z}/policy?name=keyclerk-writer")[1] if x["name"] == "keyclerk-writer"][0]["id"]
    for name, rtype, scopes in (("keyclerk-writer-groups", "Groups", ["view", "manage", "view-members", "manage-membership"]),
                                ("keyclerk-writer-users", "Users", ["view", "manage-group-membership"])):
        req("POST", f"{Z}/permission/scope", {"name": name, "resourceType": rtype, "scopes": scopes, "policies": [pol],
                                              "decisionStrategy": "UNANIMOUS"}, ok=(201, 409))


def desk_client() -> None:
    cid = ensure_client({"clientId": "keyclerk-desk", "enabled": True, "protocol": "openid-connect", "publicClient": True,
                         "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
                         "frontchannelLogout": False, "fullScopeAllowed": False,
                         "redirectUris": [f"{DESK_URL}/callback"], "webOrigins": [DESK_URL],
                         "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": DESK_URL + "/",
                                        # the broker tells the desk a session ended, on the pod's loopback (F-26)
                                        "backchannel.logout.url": "http://127.0.0.1:8091/backchannel-logout",
                                        "backchannel.logout.session.required": "true"}})
    if "anchor" not in mappers(cid):             # the person's anchor in the tokens: the desk acts as that person
        req("POST", f"{R}/clients/{cid}/protocol-mappers/models", {
            "name": "anchor", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {"user.attribute": "anchor", "claim.name": "anchor", "jsonType.label": "String",
                       "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}})
    req("POST", f"{R}/clients/{cid}/scope-mappings/realm", [req("GET", f"{R}/roles/keyclerk-viewer")[1]])


def client_policies() -> None:
    req("PUT", f"{R}/client-policies/profiles", {"profiles": [{
        "name": "relikey-secure", "description": "PKCE, no implicit or password grant, back-channel logout only",
        "executors": [{"executor": "pkce-enforcer", "configuration": {"auto-configure": "false"}},
                      {"executor": "reject-implicit-grant", "configuration": {"auto-configure": "false"}},
                      # explicit: an empty configuration leaves auto-configure null and Keycloak 26.8.1 then throws
                      # a NullPointerException on every later client creation (found by the full-stack run, add_edge)
                      {"executor": "reject-ropc-grant", "configuration": {"auto-configure": "false"}},
                      {"executor": "secure-logout", "configuration": {"allow-front-channel-logout": "false",
                                                                      "auto-configure": "false"}}]}]})
    req("PUT", f"{R}/client-policies/policies", {"policies": [{
        "name": "relikey-all-clients", "description": "every client of the realm", "enabled": True,
        "conditions": [{"condition": "any-client", "configuration": {}}], "profiles": ["relikey-secure"]}]})


def passkey_flow() -> None:
    """Passkey-only sign-in (contract C-05): identity first, then a person with a passwordless passkey signs in with it and
    is never asked for a password; a person without one (the first sign-in) uses the temporary password, and the required
    actions make them set one and register a passkey. Bound as the realm's browser flow, so the desk, approvals and every
    edge's Warpgate inherit it. The full-stack run found the stock flow accepting the password alone after a passkey."""
    from urllib.parse import quote
    top, forms, pk, first = "relikey-browser", "relikey-forms", "relikey-passkey", "relikey-first-sign-in"
    flows = {f["alias"]: f for f in (req("GET", f"{R}/authentication/flows")[1] or [])}
    if top in flows and not any(e.get("providerId") == "conditional-user-configured"
                                for e in req("GET", f"{R}/authentication/flows/{quote(top)}/executions")[1] or []):
        # an earlier build keyed on conditional-credential, which means a credential USED in this sign-in, not one the
        # person has: it always took the password branch (full-stack run). Unbind, remove and build it again.
        req("PUT", R, {"browserFlow": "browser"})
        req("DELETE", f"{R}/authentication/flows/{flows[top]['id']}")
        for f in req("GET", f"{R}/authentication/flows")[1] or []:
            if f["alias"] in (forms, pk, first):
                req("DELETE", f"{R}/authentication/flows/{f['id']}", ok=(200, 204, 404))
        flows = {f["alias"]: f for f in (req("GET", f"{R}/authentication/flows")[1] or [])}
    if top not in flows:
        req("POST", f"{R}/authentication/flows", {"alias": top, "description": "passkey-only, with a password only for the "
                    "first sign-in (ReliKey C-05)", "providerId": "basic-flow", "topLevel": True, "builtIn": False})

        def ex(flow, provider):
            req("POST", f"{R}/authentication/flows/{quote(flow)}/executions/execution", {"provider": provider})

        def sub(flow, alias):
            req("POST", f"{R}/authentication/flows/{quote(flow)}/executions/flow",
                {"alias": alias, "type": "basic-flow", "description": "", "provider": "registration-page-form"})

        ex(top, "auth-cookie"); sub(top, forms)
        ex(forms, "auth-username-form"); sub(forms, pk); sub(forms, first)
        # the passkey branch runs when the person HAS a passwordless passkey (user-configured: its authenticator is set
        # up for them); the first-sign-in branch runs only when the passkey branch did not
        ex(pk, "conditional-user-configured"); ex(pk, "webauthn-authenticator-passwordless")
        ex(first, "conditional-sub-flow-executed"); ex(first, "auth-password-form")
        want = {(top, "auth-cookie"): "ALTERNATIVE", (top, forms): "ALTERNATIVE", (forms, "auth-username-form"): "REQUIRED",
                (forms, pk): "CONDITIONAL", (forms, first): "CONDITIONAL",
                (pk, "conditional-user-configured"): "REQUIRED", (pk, "webauthn-authenticator-passwordless"): "REQUIRED",
                (first, "conditional-sub-flow-executed"): "REQUIRED", (first, "auth-password-form"): "REQUIRED"}
        for flow in (top, forms, pk, first):
            for e in req("GET", f"{R}/authentication/flows/{quote(flow)}/executions")[1] or []:
                if e.get("level", 0) != 0:
                    continue                                   # set where it lives, through its own flow
                key = (flow, e.get("providerId") or e.get("displayName"))
                if key in want:
                    req("PUT", f"{R}/authentication/flows/{quote(flow)}/executions", {**e, "requirement": want[key]})
                if e.get("providerId") == "conditional-sub-flow-executed":
                    req("POST", f"{R}/authentication/executions/{e['id']}/config",
                        {"alias": "relikey-no-passkey", "config": {"flow_to_check": pk, "check_result": "not-executed"}})
    _, rep = req("GET", R)
    if rep.get("browserFlow") != top:
        req("PUT", R, {"browserFlow": top})


def people(path: Path) -> None:
    """The first people, from install.py. A person who exists already is left as they are."""
    for p in json.loads(path.read_text(encoding="utf-8")):
        req("POST", f"{R}/users", {"username": p["username"], "email": p["email"], "emailVerified": True, "enabled": True,
                                   "firstName": p["first_name"], "lastName": p["last_name"],
                                   "attributes": {"anchor": [p["anchor"]]},
                                   "credentials": [{"type": "password", "value": p["password"], "temporary": True}],
                                   "requiredActions": ["UPDATE_PASSWORD", "webauthn-register-passwordless"]},
            ok=(201, 409))


def edge_client(edge: str, warpgate_url: str, secret: str) -> None:
    """One edge's Warpgate client, as lab/e2e/sso_run.py proved it (decision 0010)."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", edge):
        raise SystemExit("realm setup: an edge name is lower-case letters, digits and dashes")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?", warpgate_url.rstrip("/")):
        raise SystemExit("realm setup: Warpgate's external URL is https://host[:port], nothing after it")
    if len(secret) < 32:
        raise SystemExit("realm setup: the client secret on stdin is too short")
    ensure_client({"clientId": f"warpgate-{edge}", "enabled": True, "protocol": "openid-connect", "publicClient": False,
                   "secret": secret, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                   "implicitFlowEnabled": False, "serviceAccountsEnabled": False, "frontchannelLogout": False,
                   "redirectUris": [warpgate_url.rstrip("/") + "/@warpgate/api/sso/return"],
                   "attributes": {"pkce.code.challenge.method": "S256"}})
    print(f"realm {REALM}: client warpgate-{edge} for {warpgate_url}")


def fleet_client(page_url: str, secret: str) -> None:
    """The fleet page's client (decision 0026 point 13): confidential, PKCE, back-channel logout on the pod's loopback;
    a client role fleet-operator, in the ID token, admits. No realm role, and full scope off: only this client's own
    role reaches its tokens, so no default-roles path grants the page."""
    if not re.fullmatch(r"https://[a-z0-9.-]+(:[0-9]{1,5})?", page_url.rstrip("/")):
        raise SystemExit("realm setup: the fleet page's URL is https://host[:port], nothing after it")
    if len(secret) < 32:
        raise SystemExit("realm setup: the client secret on stdin is too short")
    cid = ensure_client({"clientId": "relikey-fleet", "enabled": True, "protocol": "openid-connect",
                         "publicClient": False, "secret": secret, "standardFlowEnabled": True,
                         "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
                         "serviceAccountsEnabled": False, "frontchannelLogout": False, "fullScopeAllowed": False,
                         "redirectUris": [page_url.rstrip("/") + "/callback"],
                         "attributes": {"pkce.code.challenge.method": "S256",
                                        "backchannel.logout.url": "http://127.0.0.1:8094/backchannel-logout",
                                        "backchannel.logout.session.required": "true"}})
    if req("GET", f"{R}/clients/{cid}/roles/fleet-operator", ok=(200, 404))[0] == 404:
        req("POST", f"{R}/clients/{cid}/roles", {"name": "fleet-operator",
                                                  "description": "sees the fleet page (read-only)"})
    role = req("GET", f"{R}/clients/{cid}/roles/fleet-operator")[1]
    req("POST", f"{R}/clients/{cid}/scope-mappings/clients/{cid}", [role])
    if "fleet roles" not in mappers(cid):
        req("POST", f"{R}/clients/{cid}/protocol-mappers/models", {
            "name": "fleet roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-client-role-mapper",
            "config": {"usermodel.clientRoleMapping.clientId": "relikey-fleet", "multivalued": "true",
                       "claim.name": "resource_access.${client_id}.roles", "jsonType.label": "String",
                       "id.token.claim": "true", "access.token.claim": "false", "userinfo.token.claim": "false"}})
    print(f"realm {REALM}: client relikey-fleet for {page_url}")


def fleet_grant(username: str, grant: bool) -> None:
    users = req("GET", f"{R}/users?username={urllib.parse.quote(username)}&exact=true")[1]
    if not users:
        raise SystemExit(f"realm setup: no account {username} in realm {REALM}; give the broker username exactly "
                         "(deploy/secrets/people.json lists the seeded ones)")
    cid = client_id("relikey-fleet")
    role = req("GET", f"{R}/clients/{cid}/roles/fleet-operator")[1]
    req("POST" if grant else "DELETE", f"{R}/users/{users[0]['id']}/role-mappings/clients/{cid}", [role])
    print(f"realm {REALM}: {username} {'holds' if grant else 'no longer holds'} fleet-operator")


VENDOR_DENY, VENDOR_PASSKEY = "relikey-vendor-unlinked", "relikey-vendor-passkey"


def vendor_flows() -> None:
    """The two flows every vendor provider uses: the first-broker-login flow denies (an identity not yet linked to a
    person gets nothing: no account is created and no e-mail is trusted to find one), and the post-broker-login flow asks
    for the person's passkey when they have one. A person without one yet passes to their required action, which
    registers it before any session exists: Keycloak fails a flow whose every step is skipped, so that branch needs its
    own step. vendor_link refuses a person with neither a passkey nor that required action, so the branch is never a way
    around the passkey."""
    from urllib.parse import quote
    check, first = "relikey-vendor-passkey-check", "relikey-vendor-first-passkey"
    flows = {f["alias"] for f in (req("GET", f"{R}/authentication/flows")[1] or [])}

    def ex(flow, provider):
        req("POST", f"{R}/authentication/flows/{quote(flow)}/executions/execution", {"provider": provider})

    def sub(flow, alias):
        req("POST", f"{R}/authentication/flows/{quote(flow)}/executions/flow",
            {"alias": alias, "type": "basic-flow", "description": "", "provider": "registration-page-form"})

    if VENDOR_DENY not in flows:
        req("POST", f"{R}/authentication/flows", {"alias": VENDOR_DENY, "description": "a vendor identity not linked to a "
                    "person is denied (ReliKey 0018)", "providerId": "basic-flow", "topLevel": True, "builtIn": False})
        ex(VENDOR_DENY, "deny-access-authenticator")
    if VENDOR_PASSKEY not in flows:
        req("POST", f"{R}/authentication/flows", {"alias": VENDOR_PASSKEY, "description": "the person's ReliKey passkey "
                    "after the vendor's sign-in (ReliKey 0018)", "providerId": "basic-flow", "topLevel": True, "builtIn": False})
        sub(VENDOR_PASSKEY, check); sub(VENDOR_PASSKEY, first)
        ex(check, "conditional-user-configured"); ex(check, "webauthn-authenticator-passwordless")
        ex(first, "conditional-sub-flow-executed"); ex(first, "allow-access-authenticator")
    want = {(VENDOR_DENY, "deny-access-authenticator"): "REQUIRED",
            (VENDOR_PASSKEY, check): "CONDITIONAL", (VENDOR_PASSKEY, first): "CONDITIONAL",
            (check, "conditional-user-configured"): "REQUIRED", (check, "webauthn-authenticator-passwordless"): "REQUIRED",
            (first, "conditional-sub-flow-executed"): "REQUIRED", (first, "allow-access-authenticator"): "REQUIRED"}
    for flow in (VENDOR_DENY, VENDOR_PASSKEY, check, first):
        for e in req("GET", f"{R}/authentication/flows/{quote(flow)}/executions")[1] or []:
            key = (flow, e.get("providerId") or e.get("displayName"))
            if e.get("level", 0) == 0 and key in want and e.get("requirement") != want[key]:
                req("PUT", f"{R}/authentication/flows/{quote(flow)}/executions", {**e, "requirement": want[key]})
            if e.get("providerId") == "conditional-sub-flow-executed" and not e.get("authenticationConfig"):
                req("POST", f"{R}/authentication/executions/{e['id']}/config",
                    {"alias": "relikey-vendor-no-passkey", "config": {"flow_to_check": check, "check_result": "not-executed"}})
    ra = req("GET", f"{R}/authentication/required-actions/webauthn-register-passwordless")[1]
    if ra and not (ra.get("enabled") and ra.get("defaultAction")):
        req("PUT", f"{R}/authentication/required-actions/webauthn-register-passwordless",
            {**ra, "enabled": True, "defaultAction": True})    # every new person registers a passkey


def vendor_idp(alias: str, issuer: str, client: str, display: str, secret: str) -> None:
    """A vendor's OpenID provider. Endpoints come from its discovery document over https; tokens are checked against its
    published keys; PKCE; nothing is imported or stored from it."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", alias):
        raise SystemExit("realm setup: a vendor alias is lower-case letters, digits and dashes")
    issuer = issuer.rstrip("/")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?", issuer) and not os.environ.get("KC_URL"):
        raise SystemExit("realm setup: the vendor's issuer is an https URL")
    if not secret:
        raise SystemExit("realm setup: the vendor client's secret comes on stdin")
    with urllib.request.urlopen(issuer + "/.well-known/openid-configuration", timeout=30) as r:
        meta = json.loads(r.read())
    if meta.get("issuer", "").rstrip("/") != issuer:
        raise SystemExit(f"realm setup: the discovery document names issuer {meta.get('issuer')!r}, not {issuer!r}")
    have = {f["alias"] for f in req("GET", f"{R}/authentication/flows")[1]}
    if not {VENDOR_DENY, VENDOR_PASSKEY} <= have:   # made by the full setup (login flows need the bootstrap admin)
        raise SystemExit("realm setup: the vendor sign-in flows are missing: run `realm.py vendor-flows` as the bootstrap "
                         "admin once, then add the vendor")
    rep = {"alias": alias, "displayName": display, "providerId": "oidc", "enabled": True, "trustEmail": False,
           "storeToken": False, "addReadTokenRoleOnCreate": False, "linkOnly": False, "hideOnLogin": False,
           "firstBrokerLoginFlowAlias": VENDOR_DENY, "postBrokerLoginFlowAlias": VENDOR_PASSKEY,
           "config": {"issuer": meta["issuer"], "authorizationUrl": meta["authorization_endpoint"],
                      "tokenUrl": meta["token_endpoint"], "jwksUrl": meta["jwks_uri"], "useJwksUrl": "true",
                      "validateSignature": "true", "clientId": client, "clientSecret": secret,
                      "clientAuthMethod": "client_secret_post", "pkceEnabled": "true", "pkceMethod": "S256",
                      "defaultScope": "openid", "syncMode": "IMPORT", "disableUserInfo": "true",
                      "backchannelSupported": "false", "acceptsPromptNoneForwardFromClient": "false"}}
    if req("POST", f"{R}/identity-provider/instances", rep, ok=(201, 409))[0] == 409:
        have = req("GET", f"{R}/identity-provider/instances/{alias}")[1]
        req("PUT", f"{R}/identity-provider/instances/{alias}", {**have, **rep, "config": {**have["config"], **rep["config"]}})
    print(f"realm {REALM}: vendor provider {alias} ({meta['issuer']}); unlinked identities are denied")


def vendor_link(username: str, alias: str, subject: str) -> None:
    """Link one person to their identity at a vendor's provider, by that provider's subject (its immutable id for them)."""
    users = [u for u in (req("GET", f"{R}/users?exact=true&username={urllib.parse.quote(username)}")[1] or [])
             if u["username"] == username]
    if not users:
        raise SystemExit(f"realm setup: no person {username!r}; provision them first")
    if not subject or len(subject) > 255:
        raise SystemExit("realm setup: the subject is the provider's id for the person, 1 to 255 characters")
    uid = users[0]["id"]
    has_passkey = any(c.get("type") == "webauthn-passwordless" for c in req("GET", f"{R}/users/{uid}/credentials")[1] or [])
    if not has_passkey and "webauthn-register-passwordless" not in (users[0].get("requiredActions") or []):
        raise SystemExit(f"realm setup: {username} has no passkey and no passkey to register; the vendor's sign-in alone "
                         f"must never be enough. Add the required action webauthn-register-passwordless, then link")
    for link in req("GET", f"{R}/users/{uid}/federated-identity")[1] or []:
        if link["identityProvider"] == alias:
            if link["userId"] == subject:
                print(f"realm {REALM}: {username} already linked at {alias}")
                return
            raise SystemExit(f"realm setup: {username} is linked to another subject at {alias}; unlink it first, on purpose")
    req("POST", f"{R}/users/{uid}/federated-identity/{alias}", {"identityProvider": alias, "userId": subject, "userName": subject})
    print(f"realm {REALM}: {username} linked to their identity at {alias}")


def check_scim() -> None:
    """The writer's token opens the realm's SCIM endpoint: what the reconciler will need on its first run."""
    _, body = req("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", auth=False, form={
        "grant_type": "client_credentials", "client_id": "keyclerk-writer",
        "client_secret": Path(SERVICE_CLIENTS["keyclerk-writer"][2]).read_text(encoding="utf-8").strip()})
    r = urllib.request.Request(f"{KC}/realms/{REALM}/scim/v2/Users?count=1",
                               headers={"Authorization": "Bearer " + body["access_token"], "Accept": "application/scim+json"})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            print(f"realm {REALM}: SCIM answers the writer ({resp.status})")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"realm setup: SCIM refused the writer ({e.code}); the reconciler would fail the same way") from None


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in ("edge", "vendor", "fleet") and Path(SETUP_SECRET).exists():
        _token["as"] = "setup"                    # clients and identity providers: the realm's own setup client
    if len(sys.argv) == 2 and sys.argv[1] == "setup-client":
        wait_for_broker()
        setup_client()
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "vendor-flows":
        wait_for_broker()
        vendor_flows()
        print(f"realm {REALM}: vendor sign-in flows ready")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "edge":
        wait_for_broker()
        edge_client(sys.argv[2], sys.argv[3], sys.stdin.readline().strip())
        return 0
    if len(sys.argv) == 6 and sys.argv[1] == "vendor":
        wait_for_broker()
        vendor_idp(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.stdin.readline().strip())
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "vendor-link":
        wait_for_broker()
        vendor_link(sys.argv[2], sys.argv[3], sys.argv[4])
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "fleet":
        wait_for_broker()
        fleet_client(sys.argv[2], sys.stdin.readline().strip())
        return 0
    if len(sys.argv) == 3 and sys.argv[1] in ("fleet-grant", "fleet-revoke"):
        wait_for_broker()
        fleet_grant(sys.argv[2], sys.argv[1] == "fleet-grant")
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "passkey":    # bring an existing realm to passkey-only sign-in
        wait_for_broker()
        passkey_flow()
        print(f"realm {REALM}: passkey-only browser flow bound")
        return 0
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    wait_for_broker()
    realm()
    service_clients()
    writer_permissions()
    desk_client()
    setup_client()
    client_policies()
    passkey_flow()
    vendor_flows()                                # realm-wide; adding a vendor later needs no login-flow rights
    people(Path(sys.argv[1]))
    check_scim()
    print(f"realm {REALM}: ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
