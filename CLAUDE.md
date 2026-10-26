# CLAUDE.md

`AGENTS.md` is the canonical guide. Read it first; this file only adds
Claude-specific working notes and does not repeat it.

- Read `AGENTS.md` before your first edit in a session, and again before you
  claim a change is finished.
- Run the offline suite before claiming anything works: `go build ./...`,
  `go vet ./...`, `go test ./...`. It needs no network and must pass.
- The live suites need `WARP_LIVE=1` plus real internet, and they register real
  Cloudflare accounts. Do not run them by reflex, and never in CI.
- Do not add comments beyond the one-line policy in `AGENTS.md`. No banners, no
  restating the code.
- Do not commit, push, stash, reset or create branches unless the user asks.
- Never write account material into the repository: no `identity.json`, no
  `warp-data/`, no fresh `stress_*.txt` reports. Use a temp path for anything
  generated.
- `gofmt` every Go file you touch before you report back.
- Keep changes inside this repository's files. Do not edit `go.mod` or other
  agents' work in progress without being asked.
