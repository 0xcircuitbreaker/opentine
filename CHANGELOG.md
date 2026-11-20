# Changelog

## Unreleased — Security and integrity audit

- Authentication, share-token, admin and signup throttles now key clients the
  same way the connection limiter does: IPv4 address or IPv6 /64 (IPv4-mapped
  addresses fold to IPv4). A host rotating source addresses inside its /64 can
  no longer reset its lockout every five guesses or flood out another client's
  lockout record.
