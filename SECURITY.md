# Security Policy

`bymax-auth` / `@bymax-one/rust-auth` is authentication and authorization
infrastructure, so a vulnerability here can affect every consumer. We treat
security reports as a first-class priority.

## Supported versions

No release has been published yet, so there is no supported version today. Once a
release ships, the latest released minor receives security fixes; older lines are
supported on a best-effort basis and any change is announced in the release notes.

A report against the code on the default branch is still welcome: it is handled
the same way, and it lands before the first release.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
vulnerability** — public disclosure before a fix endangers every consumer.

Report it privately through either channel:

- **GitHub Security Advisories** — use *"Report a vulnerability"* on the
  repository's **Security** tab (preferred — it lets us collaborate on a fix in
  a private fork).
- **Email** — the security contact is **support@bymax.one**.

Please include the affected crate/package and version, a description and impact
assessment, and a minimal reproduction where possible.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity rating within 7 business days.
- **Coordinated disclosure**: we agree on a timeline, ship a fix, publish an
  advisory, and **credit you** — unless you prefer to remain anonymous.

Because the compiled WASM edge verifier ships inside the npm package, a fix that
touches only that path still triggers a patched npm release so consumers receive
the rebuilt binary.
