# Changelog

All notable changes to burpwn are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial workspace scaffold: `burpwn-store`, `burpwn-tls`, `burpwn-proxy`, `burpwn-sandbox`,
  `burpwn-wrap`, `burpwn-cli`, `burpwn-mcp` crates and the `burpwn` binary.
- Validated the make-or-break assumption: a rootless `unshare --user --net` namespace with an
  in-namespace nftables `REDIRECT` delivers connections to an in-namespace listener with the correct
  original destination recovered via `SO_ORIGINAL_DST`, with full request/response round-trip.
