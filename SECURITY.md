# Security

If you discover a security vulnerability, please do not open a public issue.

Instead, contact the maintainer(s) privately.

## Notes

- This service is typically run in a LAN; if you expose it externally, enable UI Basic Auth (`DASH_BASIC_AUTH_USER` / `DASH_BASIC_AUTH_PASS`) and put it behind a reverse proxy.
- Never commit `.env` or Jira tokens.
