PINGS: Reliable one-line notifications policy

User instruction (saved):
- After every code push/commit that affects production or deploys, send a single one-line WhatsApp with: "<Phase or description> pushed — <short-sha>. Redeploy now. Tests: health / public HTML / login→dashboard".
- Mirror the same one-line message in the chat here immediately.
- If WhatsApp delivery fails, retry and still mirror in chat so the user always sees the ping.
- Only send more verbose diagnostics if the user requests them; otherwise keep messages short and action-oriented.

When to send:
- After Phase 1, Phase 2, Phase 3 commits.
- After hotfix commits that require redeploy.
- After DB migrations and schema changes.

Why:
- The user relies on these pings to know when to trigger deploys and to avoid having to repeatedly ask for updates.

Stored by Clawdbot on 2026-01-31.
