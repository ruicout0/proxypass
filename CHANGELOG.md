# Changelog

## [0.2.5](https://github.com/ruicout0/proxypass/compare/v0.2.4...v0.2.5) (2026-08-14)


### Bug Fixes

* use macOS-native config path instead of XDG ([246f457](https://github.com/ruicout0/proxypass/commit/246f457ad9155ec81ff501eeba8eb4691bd00174))

## [0.2.4](https://github.com/ruicout0/proxypass/compare/v0.2.3...v0.2.4) (2026-08-14)


### Performance Improvements

* remove worker_threads cap, cache PAC per-host, pool upstream connections, 64KB copy buffer ([e233c75](https://github.com/ruicout0/proxypass/commit/e233c754ebed9854d08368a10b9d784f9f4bcba8))
* switch opt-level from z to 3 ([3aa3771](https://github.com/ruicout0/proxypass/commit/3aa37710e9ddc360a5e45cb6a692b47f37e19055))
* switch opt-level from z to 3 ([160561f](https://github.com/ruicout0/proxypass/commit/160561fd7cb1223795aeb8617a608e918064fa72))

## [0.2.3](https://github.com/ruicout0/proxypass/compare/v0.2.2...v0.2.3) (2026-08-14)


### Performance Improvements

* **proxy:** enable TCP_NODELAY on all upstream connections ([62111a2](https://github.com/ruicout0/proxypass/commit/62111a28e235460dd23dc37f0c177990c8c7af69))
* **proxy:** TCP_NODELAY + socket buffer tuning for proxy throughput ([fc4de75](https://github.com/ruicout0/proxypass/commit/fc4de75f350411031678d04fa78fe706cbaad4cf))
* **proxy:** tune socket buffers + TCP_NODELAY on all connections ([a7196b5](https://github.com/ruicout0/proxypass/commit/a7196b553ecc33bbd6a32e48a6c869028b0cedd8))

## [0.2.2](https://github.com/ruicout0/proxypass/compare/v0.2.1...v0.2.2) (2026-08-14)


### Bug Fixes

* **auth:** use default credential instead of pre-acquired cred for GSSAPI ([13c9772](https://github.com/ruicout0/proxypass/commit/13c9772a26475acf0948484f4bc774e660ca92e8))
* **proxy:** fall back to Basic auth when Kerberos Negotiate fails ([21b73b8](https://github.com/ruicout0/proxypass/commit/21b73b8099f93531a9a87904d22e39f89e0c2923))
* **proxy:** fall back to Basic auth when Kerberos Negotiate fails ([bbed31e](https://github.com/ruicout0/proxypass/commit/bbed31ebe6b3650c67c6c62d623924ac3cf55975))

## [0.2.1](https://github.com/ruicout0/proxypass/compare/v0.2.0...v0.2.1) (2026-08-13)


### Bug Fixes

* **proxy:** cache SPNEGO token to avoid repeated GSSAPI handshake ([43bc846](https://github.com/ruicout0/proxypass/commit/43bc8465394e5529d75db6aa76cfc5e7c845aa96))

## [0.2.0](https://github.com/ruicout0/proxypass/compare/v0.1.1...v0.2.0) (2026-08-12)


### Features

* **pac:** fall back to DIRECT when PAC fetch fails after cache expiry ([61b7df9](https://github.com/ruicout0/proxypass/commit/61b7df95204230b3b4f3ddf39f68c9e6c3262af3))


### Bug Fixes

* **pac:** aggressive PAC unreachable fallback + network change detection ([724347e](https://github.com/ruicout0/proxypass/commit/724347e914b30598bddf86e685c259c1a55d9128))

## [0.1.1](https://github.com/ruicout0/proxypass/compare/v0.1.0...v0.1.1) (2026-08-12)


### Bug Fixes

* fix boot of proxy ([adb1fd7](https://github.com/ruicout0/proxypass/commit/adb1fd77f759820c44f54a4756f01900c9968dee))
* fix boot of proxy ([594ce96](https://github.com/ruicout0/proxypass/commit/594ce969ce40cd1ba94a0b522d4cc58b4f938cc4))
* **formula:** add v prefix to tarball filenames in URLs ([5dccbb9](https://github.com/ruicout0/proxypass/commit/5dccbb9f7e665dbc659ddb83441149d830cb2646))
* **formula:** correct SHAs and v-prefix URLs ([1d76d4f](https://github.com/ruicout0/proxypass/commit/1d76d4fa20cdc668146e51c10194fbf96ee737a8))
* workflows for homebridge ([588dbd7](https://github.com/ruicout0/proxypass/commit/588dbd717891b662db0c4b4c249d880acb31ad57))
* workflows for homebridge ([9d07f27](https://github.com/ruicout0/proxypass/commit/9d07f277d7f452b2f71306cc39d1861004e874c6))
