# Security Policy

## Reporting a vulnerability

If you find a security issue in iam-privesc-lens itself, for example a crafted input that causes code
execution or an analysis bug that hides a real escalation path, please report it privately through
GitHub's "Report a vulnerability" (Security Advisories) on this repository instead of opening a public issue.
Please include a minimal synthetic reproduction.

## Scope and safe use

- The tool analyses exports offline. Only `iam-privesc-lens fetch` contacts AWS, and it calls only
  `iam:GetAccountAuthorizationDetails`.
- Authorization-details exports describe your entire IAM configuration. Treat them as sensitive and do
  not attach real exports to issues.
- Use the tool only on accounts you own or are authorised to audit.
