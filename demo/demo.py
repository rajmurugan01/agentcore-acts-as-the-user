#!/usr/bin/env python3
"""Runs the scripted cases against the two deployed gateways and prints a verdict table.

The 'agent' here is a deterministic stand-in for whatever the model decides to call. That is deliberate:
enforcement must not depend on what the model decides, so the demo removes the model from the loop.
"""
import json, os, sys, time, urllib.request, urllib.error, base64
import boto3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = json.load(open(os.path.join(ROOT, "cdk", "cdk.outputs.json")))["AgentcoreActsAsUser"]
REGION = OUT["Region"]
PW = "Demo-Passw0rd!"  # throwaway users in a throwaway pool, destroyed with the stack
cog = boto3.client("cognito-idp", region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION).Table(OUT["LedgerTable"])


def ensure_user(name, groups=()):
    try:
        cog.admin_create_user(UserPoolId=OUT["UserPoolId"], Username=name, MessageAction="SUPPRESS")
    except cog.exceptions.UsernameExistsException:
        pass
    cog.admin_set_user_password(UserPoolId=OUT["UserPoolId"], Username=name, Password=PW, Permanent=True)
    for g in groups:
        cog.admin_add_user_to_group(UserPoolId=OUT["UserPoolId"], Username=name, GroupName=g)


def token(name):
    r = cog.admin_initiate_auth(UserPoolId=OUT["UserPoolId"], ClientId=OUT["ClientId"],
                                AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                                AuthParameters={"USERNAME": name, "PASSWORD": PW})
    return r["AuthenticationResult"]["AccessToken"]


def claims(tok):
    p = tok.split(".")[1]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def call(gateway_url, tok, repo, requested_by):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "github___open_pr",
                       "arguments": {"repo": repo, "title": f"change by {requested_by}", "requested_by": requested_by}}}
    req = urllib.request.Request(gateway_url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, {"raw": raw}


def ledger_count():
    n, kw = 0, {}
    while True:
        r = ddb.scan(Select="COUNT", **kw); n += r["Count"]
        if "LastEvaluatedKey" not in r: return n
        kw = {"ExclusiveStartKey": r["LastEvaluatedKey"]}


def verdict(status, body):
    if body.get("result", {}).get("isError"):
        return "DENIED", json.dumps(body["result"]["content"])[:110]
    if "error" in body or status >= 400:
        return "DENIED", json.dumps(body.get("error") or body)[:110]
    return "ALLOWED", json.dumps(body.get("result", {}).get("content"))[:110]


def run(label, gw, tok, repo, requested_by, expect):
    before = ledger_count()
    status, body = call(gw, tok, repo, requested_by)
    v, detail = verdict(status, body)
    opened = ledger_count() - before
    ok = "PASS" if v == expect else "FAIL"
    print(f"[{ok}] {label}\n       {v:8} target invoked: {opened}  | {detail}")
    return v == expect


def main():
    ensure_user("alice", ["platform"])   # a platform engineer
    ensure_user("bob")                   # not on the platform team
    ensure_user("agent-svc", ["platform"])  # the agent's own service credential
    ensure_user("carol", ["platform", "oncall"])  # in several groups
    tok = {u: token(u) for u in ("alice", "bob", "agent-svc", "carol")}
    if "--probe" in sys.argv:
        print(json.dumps({u: claims(t) for u, t in tok.items()}, indent=1)); return
    OPEN, GUARD = OUT["OpenGatewayUrl"], OUT["GuardedGatewayUrl"]
    PI, DOCS, PAY = "acme/platform-infra", "acme/docs", "acme/payments"
    r = []
    print("\n== 1. The vulnerable baseline: the agent uses its OWN credential ==")
    r.append(run("open gateway, agent credential, asked by bob -> platform-infra", OPEN, tok["agent-svc"], PI, "bob", "ALLOWED"))
    print("\n== 2. A policy alone does not fix it: agent still uses its own credential ==")
    r.append(run("guarded gateway, agent credential, asked by bob -> platform-infra", GUARD, tok["agent-svc"], PI, "bob", "ALLOWED"))
    print("\n== 3. The fix: the agent forwards the ASKING USER's token, Gateway Policy decides ==")
    r.append(run("guarded, bob's token -> platform-infra", GUARD, tok["bob"], PI, "bob", "DENIED"))
    r.append(run("guarded, alice's token -> platform-infra", GUARD, tok["alice"], PI, "alice", "ALLOWED"))
    r.append(run("guarded, alice's token -> payments (no permit)", GUARD, tok["alice"], PAY, "alice", "DENIED"))
    r.append(run("guarded, bob's token -> docs (open to all)", GUARD, tok["bob"], DOCS, "bob", "ALLOWED"))
    print("\n== 3b. The group match is exact, not a substring ==")
    cog.admin_add_user_to_group(UserPoolId=OUT["UserPoolId"], Username="bob", GroupName="platform-readonly")
    r.append(run("guarded, bob in platform-readonly -> platform-infra", GUARD, token("bob"), PI, "bob", "DENIED"))
    cog.admin_remove_user_from_group(UserPoolId=OUT["UserPoolId"], Username="bob", GroupName="platform-readonly")
    r.append(run("guarded, carol in [platform, oncall] -> platform-infra", GUARD, tok["carol"], PI, "carol", "ALLOWED"))
    print("\n== 4. The limit: a stale claim on a still-valid token ==")
    cog.admin_add_user_to_group(UserPoolId=OUT["UserPoolId"], Username="bob", GroupName="platform")
    bob_old = token("bob")
    cog.admin_remove_user_from_group(UserPoolId=OUT["UserPoolId"], Username="bob", GroupName="platform")
    print("       (bob was on the platform team, has just been removed; his old token is still valid)")
    r.append(run("guarded, bob's OLD token -> platform-infra", GUARD, bob_old, PI, "bob", "ALLOWED"))
    r.append(run("guarded, bob's FRESH token -> platform-infra", GUARD, token("bob"), PI, "bob", "DENIED"))
    print(f"\n{sum(r)}/{len(r)} cases behaved as expected")
    sys.exit(0 if all(r) else 1)


if __name__ == "__main__":
    main()
