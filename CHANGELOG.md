# Changelog

## [0.2.0](https://github.com/roymejia2217/JameFirewall/compare/v0.1.0...v0.2.0) (2026-09-27)


### ✨ Nuevas Funcionalidades

* **ui:** integrate canonical application icon ([a1189d1](https://github.com/roymejia2217/JameFirewall/commit/a1189d12ebb3bf8f37a61b0c0cd6c714f2ab1c21))


### 🐛 Corrección de Errores

* **ci:** isolate Pester runtime cleanup ([846925b](https://github.com/roymejia2217/JameFirewall/commit/846925b3106f96bae41adf626743f4b4a6c75f6e))
* **ci:** isolate Windows acceptance boundaries ([6bc1ed3](https://github.com/roymejia2217/JameFirewall/commit/6bc1ed3312728af93d1d86c83f7b6a153d0c62eb))
* **ci:** reuse one Tk lifecycle in Windows UI contract ([ca0a528](https://github.com/roymejia2217/JameFirewall/commit/ca0a5280d37e9e98de4495a140d3aaf11ffa1a7d))
* **ci:** track PyInstaller child window in Pester ([e155f26](https://github.com/roymejia2217/JameFirewall/commit/e155f26ae53c2bb0641db508c7257f0a9be291fa))
* **firewall:** trust empty successful PowerShell queries ([ba2c684](https://github.com/roymejia2217/JameFirewall/commit/ba2c68434932f5e4889838f6c489b76fc44c4973))
* **governance:** avoid single-maintainer review deadlock ([a88a013](https://github.com/roymejia2217/JameFirewall/commit/a88a013884baf8cf474799e4801b8b0643ea8141))
* **governance:** enforce meaningful commit bodies ([50392b2](https://github.com/roymejia2217/JameFirewall/commit/50392b2b2dddf665c4587b1a7ef5e12258ac6a1f))
* **governance:** match Release Please bot identity ([94b3bc3](https://github.com/roymejia2217/JameFirewall/commit/94b3bc3e8829ae1efd18d282d72af5fc0524605f))
* **governance:** prevent published branch rewrites ([0fb5fd4](https://github.com/roymejia2217/JameFirewall/commit/0fb5fd418d17a7102d858458297de4535785fe12))
* **governance:** revalidate edited PR descriptions ([81d67ac](https://github.com/roymejia2217/JameFirewall/commit/81d67ac63010cf9efdfcbdc54dfba778a84efd59))
* **governance:** satisfy strict Ruff policy in validator ([141d34f](https://github.com/roymejia2217/JameFirewall/commit/141d34fec9f82221076be8055fe202fc93367f2a))
* **governance:** track GitHub canonical ruleset fields ([e942c41](https://github.com/roymejia2217/JameFirewall/commit/e942c41dc3d90be830777899463ce18e05863f91))
* **governance:** type Release Please PR titles ([d7878cb](https://github.com/roymejia2217/JameFirewall/commit/d7878cbe3ff840f3a791054f7f42944f6f8ebe44))
* **packaging:** collect ttkbootstrap runtime assets ([3380872](https://github.com/roymejia2217/JameFirewall/commit/33808728443db8365ac530bc68f8b5107e55e68a))
* **test:** normalize ttk button state in system E2E ([babcf45](https://github.com/roymejia2217/JameFirewall/commit/babcf45d92b176af72c8e4b82e35e39030e7461b))
* **ui:** make Tk scheduler contract explicit ([49827d6](https://github.com/roymejia2217/JameFirewall/commit/49827d629faf17e0ed9efd583f9cf098884a7ad2))
* **ui:** schedule dispatcher on the real Tk root ([f3478d0](https://github.com/roymejia2217/JameFirewall/commit/f3478d078bb2946b0b08956051c23409bf61fe83))
* **windows:** use typed pytest patch path in system E2E ([0a34a2f](https://github.com/roymejia2217/JameFirewall/commit/0a34a2f7e72dd9057c9decbe81e2e62875bb242b))


### ⚡ Mejoras de Rendimiento

* **firewall:** filter rules at the NetSecurity provider ([b829f17](https://github.com/roymejia2217/JameFirewall/commit/b829f17dfe61c973675b108b4c3849115545affd))


### ♻️ Refactorización Interna

* **governance:** ground PR metadata in published standards ([07b48a2](https://github.com/roymejia2217/JameFirewall/commit/07b48a2190a91af4db8a7298093e2e240af40363))


### 📚 Documentación

* **ci:** define the 7-Zip Windows system contract ([9e6590e](https://github.com/roymejia2217/JameFirewall/commit/9e6590eb9ef7d31b8a0b975ca3e510b3fb429d65))
* **ci:** identify the approved 7-Zip installer fixture ([4b0390f](https://github.com/roymejia2217/JameFirewall/commit/4b0390f81d78147dbbf2ae485fb03bacee9d21ff))
* **ci:** reconcile acceptance and release contracts ([56a15f7](https://github.com/roymejia2217/JameFirewall/commit/56a15f71dcaa6dfbd435d6cb558d797e585e90b1))
* **governance:** define protected main and auto-merge profile ([a71bedc](https://github.com/roymejia2217/JameFirewall/commit/a71bedc231dfbdbc0f0d947e139b1adcdd15df16))
* **governance:** define the protected-main bootstrap sequence ([62ce56f](https://github.com/roymejia2217/JameFirewall/commit/62ce56f5a21320298fdeceec31c99865c92cf018))
* **governance:** require owner review for critical harness changes ([2e0c17f](https://github.com/roymejia2217/JameFirewall/commit/2e0c17f6119f86caa683b8d7f620f3c58910c096))
