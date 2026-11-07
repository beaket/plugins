# Hardening the Beaket Go client: what makes it trustworthy to security-conscious companies

Date: 2026-11-07. Local toolchain used for the experiments: `go1.27.1 darwin/arm64` (built 2026-08-28).

How to read the evidence tags:
- **[V-src]**: verified against a primary source linked inline: Go docs or source, vendor docs, or a vendor forum answer from Apple DTS.
- **[V-exp]**: verified by a local experiment in `scratchpad/hard/`. The command and its output are summarised where the claim is made.
- **[V-code]**: read in the Beaket code (Node client, interop Go port, v3 Go draft).
- **[Inf]**: inferred or recalled from memory and not verified in this session. Treat as a lead to check.

---

## 0. Summary: the 10 measures that cut the most risk per unit of effort

| # | Measure | Defends against | Concrete setting / tool | Effort | Conflicts |
|---|---|---|---|---|---|
| 1 | **Pin the hash and verify it before every exec** (the distribution idea), with per-target hashes and an atomic install | A swapped binary from a compromised CDN, server or release, a MITM, or a partial download | SHA-256 for each `GOOS/GOARCH` in the plugin text. Download into a 0700 temp dir, check the hash, `chmod 0500`, then `rename` into place. Check again on every run, or keep the binary read-only in a user dir. **curl sets no quarantine attribute, so Gatekeeper and notarization are never consulted. The pinned hash is the only gate** [V-src] | S | Signing changes bytes, so the pin must be the hash of the *signed* artifact. See #2 |
| 2 | **Reproducible builds, checked by a second independent builder** before a hash is pinned | A compromised CI runner, a release-signing machine or a maintainer inserting code that is not in the source | `CGO_ENABLED=0 go build -trimpath -buildvcs=false`. Pin `go 1.27.x` and `toolchain go1.27.1` in go.mod, set `GOTOOLCHAIN=go1.27.1` and `GOFLAGS=-mod=readonly`. Builder B (a different CI provider or a maintainer machine) publishes its own hashes. For signed macOS binaries, compare after a gorebuild-style `StripDarwinSig` | M | **cgo (Secure Enclave, Security.framework) breaks the CGO_ENABLED=0 reproducibility story** [V-src] |
| 3 | **Strict Ed25519 verification wrapper** with matching Node behaviour | Forged records or passports under a small-order "member key", which verify for *any* message, and the two implementations disagreeing on what is valid | Before `ed25519.Verify`: reject a public key (and R) that is non-canonical (y ≥ p) or one of the 8 small-order points. Ideally use a cofactor check, `[8]A != identity`, via `filippo.io/edwards25519`. Test with the "Taming the many EdDSAs" vectors in both Go and Node | S | A cofactor check needs a non-stdlib module (a blocklist does not). See §1.3 |
| 4 | **Canonical parsing everywhere** (base64, JSON, lengths) | Malleable encodings, signature or AAD confusion, and Go/Node divergence (Node is lenient, and Go's *default* is lenient too) | `base64.StdEncoding.Strict()` plus a decode → re-encode → byte-compare. Reject `\r\n`. Check exact lengths for keys, nonces and tags. Use `json.Decoder.DisallowUnknownFields()` and a duplicate-key check. Signed and AAD bytes come from a canonical serialisation, never from a re-parse | S | none |
| 5 | **Fuzzing and differential tests against the JS client** in CI | Parser panics, crashes on hostile server data, cross-implementation drift | `go test -fuzz` on every decoder (unwrap, open record, verify passport, parse invite code). A cross-language corpus run in CI on Node and Go with byte-equal outputs. Wycheproof vectors for X25519, AES-GCM, HKDF and Ed25519 | M | none |
| 6 | **Locked-down network client** | MITM through a hostile env (`HTTPS_PROXY`, and Go 1.27 honouring `SSL_CERT_FILE` on macOS/Windows), redirects off-host, slow-loris or unbounded bodies | Your own `http.Transport{Proxy: nil or an explicit opt-in, TLSClientConfig: {MinVersion: tls.VersionTLS13, RootCAs: <explicit pool>}}`, `CheckRedirect` returning `http.ErrUseLastResponse`, timeouts, `io.LimitReader`, and a single allowed host. X25519MLKEM768 is already the default [V-src] | S | Cert pinning against corporate TLS-inspection proxies. See §4.2 |
| 7 | **CI supply-chain hygiene and provenance** | Known-vulnerable stdlib or toolchain, tampered actions, unverifiable releases | `govulncheck ./...` on PRs and on a nightly schedule (reruns against the new DB). Actions pinned by commit SHA. `go mod verify`. Stdlib-only, or an allow-list (`golang.org/x/sys`, `filippo.io/edwards25519`). GitHub artifact attestations from a **reusable workflow** for SLSA v1 Build L3 [V-src]. `gh attestation verify --signer-workflow …` | S–M | none |
| 8 | **Move long-term secrets out of the 0600 config file** | Any same-user process or malware, backups or a stolen disk image reading the member private key. Today the sealed cache key is derived from that same file-resident key, so the cache adds little at rest [V-code] | macOS: a Secure Enclave P-256 key (Touch ID optional) that wraps the file key. It needs a signed, app-like bundle with a provisioning profile [V-src]. Windows: DPAPI `CryptProtectData` (`x/sys/windows`) or a TPM key via the Platform Crypto Provider. Linux: Secret Service or a TPM; otherwise keep the file | L | **cgo or Objective-C vs the reproducible build (#2)**, and the bundle + provisioning profile vs a single binary. `purego` (dlopen without cgo) may avoid cgo [Inf] |
| 9 | **Static analysis and release gates** | Common Go footguns: ignored errors (`rand.Read`, `ecdh.GenerateKey`), integer overflow on lengths, weak file permissions | `go vet`, `staticcheck`, `gosec` (G104/G304/G302/G306…), CodeQL `go` pack. `-race` in tests. A CI check that refuses `math/rand`, `unsafe` and `InsecureSkipVerify` | S | Some gosec rules are noisy. Allow-list with comments |
| 10 | **Assurance package**: a public threat model and protocol spec, an independent audit of the crypto core and protocol, a bug bounty or a security.txt + CVD policy, and published reproducibility logs | Missed design bugs, notably the **server substituting member public keys** (no key transparency), and buyers' due-diligence questionnaires | A crypto boutique (NCC Group, Trail of Bits, Cure53, Least Authority, Radically Open Security, …). Keybase's 9 person-week NCC audit cost "> $100k" [V-src]. A small-scope estimate is $40k–$120k for 2–4 person-weeks [Inf] | M–L ($) | none |

Lower-ranked but worth doing cheaply:
- FIPS build variant (`GOFIPS140=v1.0.0`, CMVP #5247) for regulated buyers.
- `crypto/subtle.WithDataIndependentTiming` around secret-dependent code.
- Disable core dumps (`setrlimit(RLIMIT_CORE,0)`) and panic hygiene.
- `runtime/secret` only as a future Linux bonus. It is still an experiment and Linux-only [V-src].

### Conflicts to plan around
1. **cgo vs reproducibility vs stdlib-only.** Secure Enclave, Keychain ACLs bound to a code signature, and LocalAuthentication (Touch ID) are Apple frameworks. Calling them from Go normally means cgo. Then the host C toolchain becomes a build input and must itself be pinned in a fixed VM or container image. Go's own guidance on this is [V-src]. Options:
   - (a) Keep the core `CGO_ENABLED=0` and put the macOS secret-store code in a tiny separate signed helper.
   - (b) Use `github.com/ebitengine/purego` to dlopen Security.framework without cgo. This keeps `CGO_ENABLED=0` and adds one dependency [Inf].
   - (c) Build macOS with cgo on a pinned macOS/Xcode image, and have builder B use the same image version.
2. **The Secure Enclave and data-protection keychain need an app-like bundle with an embedded provisioning profile** [V-src]. That conflicts with "one binary downloaded with curl and pinned by one SHA-256". The pin then covers a zip or tar of a `.app`, or the helper is a separate artifact.
3. **Code signing changes bytes** [V-exp]. The pin is over the signed bytes. Reproducibility is proven by "the rebuilt unsigned binary equals the signed one minus its signature", which needs a gorebuild-like stripper (see §3.1). Windows Authenticode has the same issue: compare the PE with its certificate table removed.
4. **FIPS-only mode vs the protocol.** `GODEBUG=fips140=only` makes non-approved algorithms error or panic [V-src]. X25519 is not a FIPS-approved key agreement [Inf]. So the hybrid wrap cannot run under `only`. Offer a FIPS-*module* build (`GOFIPS140`), not a FIPS-*only* one. `GOFIPS140=v1.0.0` also freezes the crypto module at Go 1.24 code.
5. **Certificate pinning vs corporate TLS inspection.** Hard pinning breaks behind TLS-inspecting proxies that security-conscious companies often run. E2EE means TLS protects only metadata and the bearer token, so prefer "explicit root pool + MinVersion 1.3" over leaf pinning (see §4.2).
6. **GODEBUG env overrides `//go:debug`** [V-src]. You cannot make security GODEBUGs immutable from inside the program. Set the security-relevant knobs as **explicit API fields** (`CurvePreferences`, `RootCAs`, `MinVersion`), which do not depend on GODEBUG defaults.

---

## 1. Crypto correctness in Go

### 1.1 What is in the stdlib now (Go 1.27.1)
- `crypto/mlkem`: ML-KEM-768 and ML-KEM-1024 per FIPS 203. `NewDecapsulationKey768(seed)` takes a 64-byte seed. The stdlib tree runs Wycheproof ML-KEM tests (`src/crypto/mlkem/mlkem_wycheproof_test.go`) [V-src, local GOROOT].
- `crypto/ecdh` provides X25519, and `crypto/hkdf` is in the stdlib (since Go 1.24 [Inf]).
- `cipher.NewGCMWithRandomNonce(block)`: it prepends a random 96-bit nonce, `NonceSize()==0`, overhead is 28 bytes, and the doc says "A given key MUST NOT be used to encrypt more than 2^32 messages" [V-src, `go doc`]. The interop port already uses it for the seal blob (`tools/interop/go/core.go:52`) [V-code].
  - Team keys rotate per epoch, and the local cache key seals few messages. Both are far below 2^32, but log a counter or rotate if the cache ever seals per-record per-write.
  - For **deterministic or wrap** contexts where the key is fresh per message (HKDF from an ephemeral X25519 secret), a fixed zero nonce with `cipher.NewGCM` is safe and avoids depending on randomness. Document which is which.
- `crypto/rand.Read`: "never returns an error … crashes the program irrecoverably if an error is returned" [V-src]. The v3 and interop ports' `random()` helper ignores the return value, which is fine on Go ≥1.24 [V-code].
- Go 1.26 `cryptocustomrand=0` (the default): most crypto APIs **ignore** the caller's `io.Reader` random parameter [V-src, godebug.md]. Deterministic test vectors therefore need `testing/cryptotest.SetGlobalRandom`, which is present in the 1.27 tree [V-src, local GOROOT; exact API Inf]. Do not rely on passing a fixed reader.
- `crypto/subtle.WithDataIndependentTiming(f)` is present [V-src]. On arm64 it sets the DIT flag. Wrap custom secret-dependent code in it, and use `subtle.ConstantTimeCompare` for tokens and MACs. Go's own primitives (X25519, ML-KEM, AES-GCM with hardware AES, Ed25519 signing) are designed to be constant time [Inf; Go's stated policy]. Your own code must not branch or index on secret bytes. Comparing a public fingerprint is not secret.

### 1.2 FIPS 140-3
Source: [go.dev/doc/security/fips140](https://go.dev/doc/security/fips140) [V-src].
- `GOFIPS140=off|latest|v1.0.0|v1.26.0|inprocess|certified` is set at build time. The selected module is a frozen, checksummed zip: `GOROOT/lib/fips140/v1.0.0-c2097c7c.zip` and `v1.26.0.zip`, with `fips140.sum` [V-src, local].
- v1.0.0 is covered by **CMVP certificate #5247** and CAVP A6650. v1.26.0 is "Pending Review" (In Process) and covered by CAVP A8028, as of 2026-04-28.
- `GODEBUG=fips140=on|only`. Go's page says `only` is "not intended to be used in production". Go 1.27 adds `crypto/fips140.Enforced()` and `WithoutEnforcement(f)` [V-src, local `go doc`]. Go 1.27 also adds `fips140ems` for TLS EMS enforcement [V-src].
- FIPS mode is not supported on OpenBSD, Wasm, AIX or 32-bit Windows [V-src].
- Recommendation: ship a separate `beaket-fips` build with `GOFIPS140=certified` for customers who ask. Say in the docs that the module is validated, not the protocol. X25519 is not an approved KAS [Inf]. The ML-KEM half is FIPS 203, and treating the hybrid as approved depends on SP 800-56C/SP 800-227 combiner rules [Inf, needs a FIPS consultant].
- FIPS mode runs known-answer self-tests at startup [V-src]. That is cheap.

### 1.3 Ed25519 strictness: the most concrete correctness gap found

Local experiment [V-exp] (`scratchpad/hard/ed/main.go`, go1.27.1):
```
identity key, R=id, S=0, any msg: true        <- verifies for EVERY message
non-canonical identity key encoding: true     <- y = p+1 accepted as a public key
valid sig: true  S+L (non-canonical S): false <- S >= L is rejected
```
- What Go checks:
  - `crypto/internal/fips140/edwards25519.SetBytes` "accepts all non-canonical encodings of valid points" [V-src, source comment line 142].
  - Verification is cofactorless and compares the *re-encoded* R′ to the signature's R bytes. A non-canonical R in the signature therefore cannot match [Inf from the code shape].
  - S must be canonical [V-exp].
  - Net effect: Go accepts small-order and non-canonical **public keys**, roughly the ZIP-215 decoding leniency combined with RFC 8032's cofactorless equation [Inf].
- Node and OpenSSL refuse the small-order case (finding supplied in the brief, not re-tested here).
- Why it matters for Beaket: if the server, or a malicious member, can register an Ed25519 "public key" that is small-order, every record or passport "signed" by that member verifies in Go no matter its contents. Go and Node also disagree on validity, a consensus split.
- Fix (stdlib-only, small):
  1. When a member key is accepted (enrolment, roster fetch), reject it unless it decodes canonically: re-encode it and compare bytes, which needs the edwards25519 point type. The stdlib does not export that type, so stdlib-only code needs a constant blocklist instead.
  2. Reject the 8 small-order points, and their non-canonical encodings, by comparing against a constant blocklist (libsodium's approach [Inf]).
  3. Alternatively take one tiny dependency, [`filippo.io/edwards25519`](https://pkg.go.dev/filippo.io/edwards25519), the same code as the stdlib's internal package. Do `p, err := new(Point).SetBytes(A)`, require `bytes.Equal(p.Bytes(), A)`, and require `new(Point).MultByCofactor(p).Equal(Identity) == 0`.
  4. Apply the same rule in Node so that both refuse the same set. Add the test vectors from Chalkias, Garillot and Nikolaenko, ["Taming the many EdDSAs" (2020)](https://eprint.iacr.org/2020/1244) and [ZIP-215](https://zips.z.cash/zip-0215) to the cross-implementation corpus [Inf for exact URLs].
- A proof-of-possession at enrolment does **not** help here: the identity key "signs" every challenge [V-exp].

### 1.4 Encoding strictness
Local experiment [V-exp] (`scratchpad/hard/b64`):
```
"AR==" std=[1] OK          strict=error      <- non-zero trailing bits accepted by default
"AQ==\n" std=[1] OK         strict=[1] OK     <- newlines silently skipped by both
```
- Go's default `StdEncoding` is **not** canonical.
- Use `base64.StdEncoding.Strict()` (or `RawURLEncoding.Strict()`), reject any `\r` or `\n` explicitly, and re-encode and compare.
- Check exact decoded lengths: 32 for X25519 and Ed25519 keys, 1184 for an ML-KEM-768 encapsulation key, 1088 for its ciphertext, 64 for signatures.
- Never sign or MAC something that is later re-parsed and re-serialised. Sign the exact canonical byte string, as the v3 draft's `recordSigned(team, r)` construction does [V-code]; make sure Node builds byte-identical input.
- `encoding/json/v2`, which rejects duplicate names by default, is still behind `GOEXPERIMENT=jsonv2` in 1.27 [V-src, build tag]. With v1, detect duplicate keys yourself, or never trust fields outside the signed canonical bytes.

### 1.5 Key zeroization in Go
- Limits [Inf, well known]:
  - The GC moves and copies nothing on the heap, but it does copy stacks and grow slices.
  - `[]byte`→`string` conversions and `append` leave copies.
  - `ecdh.PrivateKey` and `mlkem.DecapsulationKey768` are opaque, with no `Zero()`.
  - So zeroization is best effort: zero your own `[]byte` buffers with `clear(b)`, avoid `string(secret)`, and keep secrets in one buffer.
- **`runtime/secret` shipped as an experiment in Go 1.26** (`GOEXPERIMENT=runtimesecret`). It is still behind the `goexperiment.runtimesecret` build tag in 1.27.1, and "currently only supported on linux/amd64 and linux/arm64. On unsupported platforms, Do will invoke f directly" [V-src: local `src/runtime/secret/secret.go`; [Go 1.26 release notes](https://go.googlesource.com/website/+/a5b778062e0b102d79aebb56be1aa72bc67b8d77/_content/doc/go1.26.md)].
  - `secret.Do` erases registers and stack, and erases heap allocations once the GC finds them unreachable.
  - It is a nice-to-have on Linux only. Do not claim it on macOS or Windows, and do not make the build depend on an experiment.
- Bigger wins than zeroization:
  - Disable core dumps: `syscall.Setrlimit(RLIMIT_CORE, 0)` on unix.
  - Do not set `GOTRACEBACK=crash`.
  - Keep the process short-lived: the CLI exits after each command.
  - Keep secrets out of argv and env (visible in `ps` and `/proc`).

---

## 2. Supply chain

| Control | Setting | Evidence |
|---|---|---|
| Stdlib-only | Already true for the interop port (`go.mod`: no requires) and the v3 draft [V-code]. If you relax it, allow-list only Go-team or Filippo modules (`golang.org/x/sys`, `filippo.io/edwards25519`) and vendor them | |
| Module integrity | `GOFLAGS=-mod=readonly`, `go mod verify` in CI. The default `GOPROXY`/`GOSUMDB` give a transparency log for any module | [Inf, standard] |
| Toolchain pinning | `go 1.27` plus `toolchain go1.27.1` in go.mod. `GOTOOLCHAIN=go1.27.1` in CI and for builder B so that `auto` cannot switch silently. Locally `GOTOOLCHAIN=auto` [V-exp, `go env`] | |
| Toolchain trust | Go toolchains are **perfectly reproducible since Go 1.21.0**, verified by `gorebuild` | [V-src: go.dev/blog/rebuild](https://go.dev/blog/rebuild) |
| Reproducible app build | `CGO_ENABLED=0 go build -trimpath -buildvcs=false` (or build from a clean checkout of the same commit). A second copy in a different directory gave identical SHA-256 (`0e376bf0…`) [V-exp]. `go version -m` shows the embedded flags. Pin `-ldflags` (for example `-s -w` or none) explicitly | [V-src] blog: "Programs without cgo can use `CGO_ENABLED=0 go build -trimpath`" |
| Second builder | Builder A is GitHub Actions in a reusable workflow. Builder B is a maintainer on another OS, or another CI (GitLab, Buildkite). Both publish `SHA256SUMS` for every `GOOS/GOARCH`. The plugin pin is updated only when A == B. Commit both sums to the repo | [Inf] design |
| Vulnerability scanning | `govulncheck ./...` (symbol-level reachability) on every PR and nightly. Also `govulncheck -mode=binary` on the release binary | [Inf] |
| Provenance | GitHub artifact attestations (`actions/attest-build-provenance`) run from a **reusable workflow**, which GitHub documents as SLSA v1.0 **Build L3**. Attestations alone are L2. Verify with `gh attestation verify file --repo org/repo --signer-workflow org/repo/.github/workflows/release.yml` | [V-src: GitHub docs](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3) |
| Signing and transparency | GitHub attestations are signed with Sigstore (Fulcio cert bound to the workflow OIDC identity, logged in Rekor for public repos) [Inf]. Alternatively `cosign sign-blob --bundle` and `cosign verify-blob --certificate-identity … --certificate-oidc-issuer https://token.actions.githubusercontent.com` | [Inf] |
| CI hardening | Pin actions by full commit SHA. `permissions:` least-privilege per job. No `pull_request_target` with checkout. Release job gated on a protected environment with required reviewers. Use OpenSSF Scorecard to track | [Inf] |

**How the pin, provenance and reproducibility fit.** The plugin Markdown carries the SHA-256s. The plugin repo's own history, through git commit signing and branch protection, is then the root of trust.
- Provenance adds "built by this workflow from this commit".
- The second builder adds "and the commit really produces these bytes".
- A careful user, or Claude, can rerun the build and compare. The verification recipe is `git checkout <tag> && CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 GOOS=… GOARCH=… go build -trimpath -buildvcs=false ./cmd/beaket && shasum -a 256`.

---

## 3. Platform

### 3.1 macOS
- **The Go linker already ad-hoc signs darwin/arm64 binaries** (`flags=0x20002(adhoc,linker-signed)`) [V-exp].
- **Developer ID + hardened runtime + notarization** are needed for browser downloads, MDM allow-listing and Brew casks. With **curl, no quarantine xattr is set, so Gatekeeper and notarization are never evaluated** [V-src: [Apple forum 706273](https://developer.apple.com/forums/thread/706273), [666452](https://developer.apple.com/forums/thread/666452)]. A bare Mach-O cannot be stapled; Gatekeeper fetches the ticket online [Inf]. Signing is still worth it: EDR and MDM policy keys on the Team ID, and keychain ACLs bind to the designated requirement.
- **Proving signed == reproducible** [V-exp + V-src]:
  - Experiment: re-sign with `codesign -f -s - --options runtime --identifier …`, then `codesign --remove-signature` on both the linker-signed and the re-signed copies.
  - Result: they **differ in 2 bytes**, the `__LINKEDIT` `vmsize`. Apple's signer page-rounds it; the linker does not.
  - So a naive "strip and compare" fails. Go's own [`gorebuild` `StripDarwinSig`](https://go.googlesource.com/build/+/refs/heads/master/cmd/gorebuild/darwin.go) removes `LC_CODE_SIGNATURE`, fixes `ncmds`/`sizeofcmds`, sets `__LINKEDIT` filesize and vmsize to the unsigned length, and truncates. Go's release verification does exactly this: "Executable binaries must match exactly after stripping code signatures" [V-src: go.dev/blog/rebuild].
  - Ship a small `verify-signed` subcommand or script that implements the same normalisation, about 80 lines with `debug/macho`.
  - Alternative (Bitcoin Core): publish **detached signatures**. Builders reproduce the unsigned binary and *attach* the signature deterministically with `signapple`, which gives a bit-identical signed artifact. Signing of standalone binaries landed in [bitcoin/bitcoin#31407](https://github.com/bitcoin/bitcoin/pull/31407) (merged 2025) [V-src via search summary].
  - cdhash: the CodeDirectory hash covers page hashes plus special slots (requirements, entitlements, Team ID). An ad-hoc re-sign therefore does not reproduce a Developer ID cdhash [Inf from format; two ad-hoc signatures gave different cdhashes in the experiment]. Use stripping, not the cdhash.
- **Keychain**:
  - Known finding: an item written by `/usr/bin/security` is readable by any same-user process through that same CLI. Its ACL trusts `/usr/bin/security`.
  - Fix: create the item from the Beaket binary itself through Security.framework, so the legacy file keychain ACL trusts *Beaket's designated requirement* (Team ID + identifier). Other processes then get a prompt [Inf; TN3137 describes the ACL model].
  - The **data protection keychain and Secure Enclave keys require entitlements authorised by a provisioning profile, which needs an app-like bundle** (`Contents/embedded.provisionprofile`, executable run from `Contents/MacOS/`). They work only in a user session [V-src: [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains), [DTS forum 125510](https://developer.apple.com/forums/thread/125510)].
  - Secure Enclave keys are P-256 only [Inf, Apple docs]. Use `SecKeyCreateEncryptedData` with `eciesEncryptionCofactorX963SHA256AESGCM` to wrap a 32-byte file key, with `kSecAccessControlBiometryCurrentSet`/`.userPresence` for Touch ID [Inf].
  - All of this means cgo/Objective-C or purego, a bundle, and a provisioning profile. That is the main conflict with #1 and #2.
- `sandbox-exec` / SBPL is documented as deprecated in its man page but still works [Inf]. Not recommended as a product dependency. The App Sandbox needs a bundle and entitlements.

### 3.2 Windows
- **Authenticode via Azure Artifact Signing** (formerly Trusted Signing) [V-src: [Microsoft code-signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)]:
  - Individuals are currently limited to the US and Canada.
  - It gives **no instant SmartScreen reputation**: reputation is per file hash and accrues over time.
  - EV certificates no longer bypass SmartScreen [V-src: [SmartScreen reputation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation)].
  - curl downloads do not carry Mark-of-the-Web, so SmartScreen does not trigger. Winget installs verify the manifest hash [Inf].
- Reproducibility: the Authenticode signature sits in the PE certificate table, and the checksum field changes. Verify by zeroing the `CheckSum` and the security directory entry and truncating the certificate table [Inf; gorebuild uses msiextract for MSIs, V-src].
- Secrets:
  - DPAPI `CryptProtectData`, user scope, through `golang.org/x/sys/windows` (pure Go syscalls, no cgo) [Inf]. It protects against other users and offline disk theft, not same-user malware.
  - TPM-bound keys via NCrypt with `MS_PLATFORM_CRYPTO_PROVIDER` (also syscalls, no cgo) [Inf]. Windows Hello for user presence [Inf].

### 3.3 Linux
- Secret Service over D-Bus (GNOME Keyring or KWallet) needs a D-Bus client dependency such as `godbus`, and it is absent on headless servers. The kernel keyring (`keyctl` via `x/sys/unix`) is session-scoped, not persistent. A TPM via `github.com/google/go-tpm` is heavyweight [Inf].
- Practical default: a 0600 file in `$XDG_CONFIG_HOME` with a 0700 dir, plus optional Secret Service.
- `runtime/secret` is Linux-only [V-src].

---

## 4. Runtime hardening

### 4.1 Network: one server, nothing else
- Do not use `http.DefaultClient`. Its transport uses `ProxyFromEnvironment` [Inf, well known]. Build a dedicated `http.Client`:
  - `Transport.Proxy = nil`. If corporate proxies must be supported, accept only an explicit `beaket config proxy` setting rather than ambient `HTTPS_PROXY`, or print the proxy in use.
  - `TLSClientConfig.MinVersion = tls.VersionTLS13`. The default minimum is still TLS 1.2 [V-src, `go doc`].
  - `CurvePreferences`: leave the default, which includes **X25519MLKEM768 since Go 1.24**, with SecP256r1MLKEM768 and SecP384r1MLKEM1024 added in 1.26 [V-src]. Or set it explicitly to `[X25519MLKEM768, X25519]` so that `GODEBUG=tlsmlkem=0` in the environment cannot drop PQ [Inf: explicit fields take precedence per doc wording].
  - **`RootCAs` explicit.** Go 1.27 added `x509sslcertoverrideplatform`, default 1, which makes macOS and Windows **load roots from `SSL_CERT_FILE`/`SSL_CERT_DIR` when set** [V-src, godebug.md]. An env var can therefore swap the trust store. Use `x509.SystemCertPool()` only after checking that those vars are unset, or embed the server's CA roots.
  - `CheckRedirect` returning `http.ErrUseLastResponse`, mirroring Node's `redirect: "manual"` [V-code, beaket.mjs:258].
  - Timeouts: `Client.Timeout`, `ResponseHeaderTimeout`. Use `io.LimitReader` on bodies and verify the request host equals the configured server.
- Env hygiene at startup: warn or refuse when `GODEBUG`, `SSL_CERT_*`, `HTTPS_PROXY` or `GOFIPS140`-like vars are present unexpectedly. `GODEBUG` env overrides `//go:debug` lines [V-src].

### 4.2 Certificate pinning: the tradeoff
- E2EE means TLS compromise exposes metadata, the **bearer token** and the ability to serve forged rosters or keys. It does not expose record plaintext.
- The real defence against a malicious or compromised server is in the protocol:
  - signed rosters,
  - member-key fingerprints verified out of band (safety numbers),
  - a key-transparency or append-only log of roster changes, like Keybase's sigchain and Merkle root [Inf; Keybase box auditor, V-src link](https://book.keybase.io/docs/teams/box-auditor).
- Leaf or SPKI pinning breaks behind TLS inspection and on key rotation. If you want it, pin a *set* of CA SPKIs (current + backup) with a remote kill-switch-free rotation plan [Inf].

### 4.3 Files
- 0700 dirs and 0600 files, created with `os.OpenFile(O_CREATE|O_EXCL, 0600)`.
- Atomic writes: write a temp file in the same dir, `f.Sync()`, then `os.Rename`, then fsync the dir. The v3 draft uses `os.WriteFile(out, …, 0o600)` [V-code, main.go:438]. It is not atomic, and it does not fix permissions on an existing file. The umask can only reduce permissions; an existing file keeps its mode.
- Refuse to read secret files whose mode is wider than 0600 or whose owner is not the user, as ssh does [Inf].
- Use `os.Root` (Go 1.24+) to confine path operations to the config dir, blocking symlink and `..` escapes [Inf: the API exists since 1.24].

### 4.4 Sandboxing
- **Linux**: Landlock via [`github.com/landlock-lsm/go-landlock`](https://pkg.go.dev/github.com/landlock-lsm/go-landlock/landlock):
  - FS rules, TCP connect rules from ABI v4, and IPC scoping from v6.
  - ABI v8+ uses `LANDLOCK_RESTRICT_SELF_TSYNC` for all threads. Earlier ABIs need libpsx via cgo for multi-threaded Go.
  - Note **GHSA-vv6c-69r6-chg9**: in BestEffort mode on V4/V5 it did not restrict TCP bind/connect [V-src via search; fixed version not confirmed].
  - Restrict to the config dir + `connect:443`. It adds a dependency.
- seccomp via `x/sys/unix` is possible but fragile with the Go runtime [Inf].
- **OpenBSD**: `unix.Pledge("stdio rpath wpath cpath inet dns")` and `unix.Unveil` in `x/sys/unix` [Inf].
- **macOS**: no supported self-sandbox for CLIs (`sandbox-exec` deprecated) [Inf].
- Ranking: low. A sandbox reduces blast radius after an RCE in a memory-safe CLI with tiny attack surface. Fuzzing (#5) addresses the same risk more cheaply.

### 4.5 Panic, log and crash hygiene
- The v3 draft uses `panic(err)` for control flow (`fromB64`, `must`) [V-code]. Replace it with returned errors. Have a top-level `recover` that prints a fixed message with no `%v` of structs that may hold keys.
- Implement `String()`/`GoString()`/`Format` on secret types to redact.
- Never put server response bodies verbatim into errors. The Node client echoes up to 300 chars of the body (`beaket.mjs:250`) [V-code]. That is fine for server text, but strip control characters: terminal escape injection into Claude's or the user's terminal.
- Default `GOTRACEBACK` prints stacks with argument words, not slice contents [Inf]. Disable core dumps.

### 4.6 Testing and analysis
- **Fuzz**: `go test -fuzz=FuzzOpenRecord -fuzztime=…` on every decoder in CI (short) and nightly (long). Keep the corpus in `testdata/fuzz`. OSS-Fuzz accepts native Go fuzzers [Inf].
- **Differential**: one JSON vectors file, generated by each implementation and consumed by the other:
  - wrap/unwrap, seal/open, sign/verify (including the invalid-key cases from §1.3),
  - invite codes, passports,
  - **negative cases**: bad base64, wrong lengths, swapped AAD.
  - CI runs `node` and `go test` on both directions. The `tools/interop/go/scenario.go` harness is the seed [V-code].
- Use Wycheproof for X25519, AES-GCM, HKDF and Ed25519 (the Ed25519 vectors include the edge cases).
- Static: `go vet`, `staticcheck`, `gosec`, GitHub CodeQL (`go` language). `go test -race`. Mutation testing is optional.

---

## 5. Assurance and what comparable products do

- **Public threat model and spec.** Publish PROTOCOL.md v3 with explicit adversaries: malicious server, malicious member, network, same-user malware (out of scope or partially), lost device. Include what Beaket can see (passports in the clear), key-rotation semantics, and the roster-trust gap.
- **Audit.** NCC Group's Keybase review was 9 person-weeks, Sep 2018, and Keybase said it invested "over $100,000" [V-src: [Keybase blog](https://www.keybase.io/blog/chat-apps-softer-than-tofu), [NCC report](https://api.keybase.io/docs-assets/blog/NCC_Group_Keybase_KB2018_Public_Report_2019-02-27_v1.3.pdf)]. For a ~1–2k LOC crypto core plus protocol, expect 2–4 person-weeks, roughly $40k–$120k at 2026 boutique rates [Inf]. OSTIF and the OpenSSF Alpha-Omega fund open-source audits [Inf]. Publish the report.
- **Bug bounty / CVD.** A `SECURITY.md` + `security.txt` with a PGP or age key and a 90-day policy come first. A paid bounty (HackerOne, Intigriti) later [Inf].
- **Comparables** [Inf unless marked]:
  - **age/rage**:
    - Go, essentially stdlib + x/crypto.
    - Small spec (C2SP).
    - Reproducible builds and signed releases with provenance.
    - It deliberately has no signatures or key server.
  - **Signal's libsignal**: Rust with Java, Swift and TypeScript bindings. One core, many bindings, which avoids the Go/Node divergence class entirely. Also an option for Beaket: make Go the only implementation and have the Node plugin shell out.
  - **Keybase**:
    - Go client.
    - Sigchains plus a Merkle root published to Bitcoin, giving key-transparency-like guarantees.
    - The team box auditor checks the server's key boxes [V-src link above].
    - NCC audit [V-src].
  - **Tailscale**: Go client. It publishes security bulletins, uses signed packages, and its Tailnet Lock gives node-key signing against a malicious coordination server. Tailnet Lock is the closest analogue to "don't trust the server with membership".
  - **1Password**: publishes a security design white paper and third-party assessments, runs a public bug bounty, and uses Secure Enclave and Touch ID through its *app*, not its CLI.

---

## 6. Observations about the current code

All [V-code] unless marked.
- `beaket.mjs:375`: `cacheKey = hkdfKey(privateKey, "cache")`. The sealed cache protects against someone who gets the cache files but not `config.json`. Anyone who can read the 0600 config can also open the cache. Moving the private key into an OS store (#8) is what gives the cache real at-rest value.
- `beaket.mjs:48`: `DEFAULT_SERVER = "https://stg.beaket.com"`, a staging host as the default. Confirm this is intended before any hardened release.
- The v3 draft has `go.mod` `go 1.27.1` with no `toolchain` line, and the interop port has `go 1.24`. Make both identical and add `toolchain`.
- `ed25519.Verify` is called directly on server-provided keys in v3 (`main.go:270, 342`). Add the §1.3 check at the point where keys enter the roster.
