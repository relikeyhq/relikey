# SPDX-License-Identifier: EUPL-1.2
"""The anchor ceremony in Chromium with a virtual authenticator (run by browser_test.go): python -P this.py PAGE BROKER.

Checks the page's script as shipped: a refused passkey prompt is explained on the page and the step can be retried; each named
officer registers and signs; someone not named is offered nothing; no script error and no policy violation at any
point; after the anchor the page offers enrolment and carries no script."""
import sys

from playwright.sync_api import expect, sync_playwright

PAGE, BROKER = sys.argv[1], sys.argv[2]
NAMES = ["ann", "bob", "cat"]


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        problems = []

        def person(name, verified=True):
            ctx = browser.new_context(ignore_https_errors=True)
            ctx.add_cookies([{"name": "who", "value": name, "url": BROKER}])
            pg = ctx.new_page()
            pg.on("pageerror", lambda e: problems.append(f"{name}: script error: {e}"))
            pg.on("console", lambda m: problems.append(f"{name}: {m.text}") if "Content Security Policy" in m.text else None)
            cdp = ctx.new_cdp_session(pg)
            cdp.send("WebAuthn.enable")
            aid = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
                "isUserVerified": verified, "automaticPresenceSimulation": True}})["authenticatorId"]
            pg.goto(PAGE + "/")
            return pg, cdp, aid

        def row(pg, name):
            return pg.locator("tr", has=pg.locator(".edge", has_text=name)).inner_text()

        people = {}
        # ann's first try: her authenticator cannot verify her, so the browser refuses the prompt (the server's own
        # refusal of an unverified answer is the Go tests'); the page says so and she can try again
        pg, cdp, aid = person("ann", verified=False)
        pg.click("#officer-register")
        # (a wait by locator: the page's policy refuses string evaluation, Playwright's wait_for_function included)
        expect(pg.locator("#anchor-msg")).to_contain_text("cancelled or timed out", timeout=30000)
        msg = pg.text_content("#anchor-msg")
        if pg.is_disabled("#officer-register"):
            fail(f"a refused registration: message {msg!r}, button disabled {pg.is_disabled('#officer-register')}")
        cdp.send("WebAuthn.setUserVerified", {"authenticatorId": aid, "isUserVerified": True})
        with pg.expect_navigation():
            pg.click("#officer-register")
        people["ann"] = pg
        for name in NAMES[1:]:
            pg, _, _ = person(name)
            with pg.expect_navigation():
                pg.click("#officer-register")
            people[name] = pg
        for name in NAMES:
            if "device-bound passkey" not in row(people["cat"], name):
                fail(f"{name} is not listed as registered: {row(people['cat'], name)!r}")
        dan, _, _ = person("dan")
        if dan.locator("button[type=button]").count() or dan.locator("script").count():
            fail("someone not named is offered a passkey step")
        for i, name in enumerate(NAMES):
            pg = people[name]
            pg.reload()
            with pg.expect_navigation():
                pg.click("#anchor-sign")
            if i < 2 and "signed" not in row(pg, name):
                fail(f"{name}'s signature is not shown: {row(pg, name)!r}")
        final = people["cat"]
        if final.locator("form[action='/slots']").count() != 1 or final.locator("script").count():
            fail("after the anchor: no enrolment form, or a script remains")
        if problems:
            fail("; ".join(problems))
        print("ok: refused prompt explained and retried; 3 officers registered and signed; anchored")
        browser.close()


main()
