- The fleet page opens enrolment slots from a browser: it sent `Referrer-Policy: no-referrer`, so browsers posted its
  forms with `Origin: null` and every slot was refused as "Sign in on the fleet page first." (#172). The policy is
  `same-origin`, and each refusal now says its own reason (no session, no admin section, another origin, an origin the
  browser withheld). The slot name's pattern is valid under the browser's `v` flag, so the browser checks it (#173).
