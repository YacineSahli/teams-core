
## 2026-10-20 CORRECTION + true state of the call-receive gap

The "network filters 8443" root cause was WRONG: portquiz.net:8443
answers 200 from this (home) WiFi — outbound 8443 is open; the skype
controller hosts simply don't listen there. And the :8443/V2 template
turns out to be the HYBRID-appliance config (applianceFqdns:"" —
empty for cloud accounts) — not the consumer cloud path at all. The
register_calling_v2 code stays (harmless, clearly-commented) but is
likely irrelevant.
TRUE OPEN STATE: consumer call invite delivery to the callee remains
unsolved. Ruled out: account tier/CID (B→A identical), TFL
registration table (live, no change), Event/Call thread markers (no
SDP), 8443/V2 appliances (hybrid-only). Our trouter session sends no
subscribe frames (only keepalive + user.activity) — the consumer web
client may subscribe per-channel at connect, or register different
appIds/keys not present as literals in its bundles.
NEXT LEAD (needs one user-gated step): sign B into teams.live.com in
a browser ONCE, call it from the rig app (A --ctl call), and capture
what the web client's connection does differently — its registrar
POSTs (DevTools) and/or its trouter WS frames. That diff ends the
guessing. Everything else (placement, messaging, naming) remains
verified working.
