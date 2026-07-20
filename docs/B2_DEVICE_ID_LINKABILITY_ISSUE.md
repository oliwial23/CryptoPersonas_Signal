# B2 (shared phantom identity): a device-linking side effect that breaks post-to-post unlinkability

The original design for hiding *which real account* sent a message called for every
member to sealed-send under one shared, server-issued `SenderCertificate` belonging
to a "phantom" account. In practice this isn't reachable through the Signal client
library (`presage`) we build on: its public API exposes no way to fetch a
certificate for an account, and no way to pass a certificate into the send path at
all — every send always uses the caller's own, automatically-fetched certificate.
Reaching the certificate machinery directly would require either forking the
library to add that capability, or bypassing it entirely and re-implementing
message delivery by hand against the lower-level protocol crate underneath it — a
substantially larger and riskier undertaking than swapping in a different
certificate was meant to be.

The implemented workaround sidesteps the problem rather than solving it directly:
instead of substituting a certificate, every member is linked as an independent
**device** of one shared phantom Signal account, using Signal's own standard
multi-device feature (the same mechanism that lets one person use Signal on a
phone and a laptop simultaneously). Each linked device generates its own real
identity key and receives its own real, honestly-issued certificate — nothing is
faked or intercepted. The certificate says "phantom" because, from the server's
perspective, that member's device genuinely is a device of the phantom account.

This introduces a leak the original design didn't have. Each linked device keeps a
fixed, persistent device number for as long as it stays linked, and that number is
visible to the recipient on every message it decrypts. So while every member
shares the same account identity, each one is still tagged with a stable,
per-member identifier. A recipient can therefore group every message sent by
device 2 together, and every message sent by device 3 together, even without
knowing who those devices actually belong to — meaning two posts from the same
member become linkable to each other. This directly undermines the
post-to-post unlinkability the content-layer encryption scheme (a separate,
already-working component using single-use per-message keys) was specifically
designed to guarantee; the delivery layer is currently reintroducing exactly the
correlation the content layer eliminates.

Two directions to close this gap, mirroring how the content layer already handles
its own single-use keys: rotate the linked device **per message** — link
immediately before sending, then unlink right after — which gives the strongest
guarantee (no two messages ever share a device number) but costs a real network
round trip to Signal's server on every single send, adding latency and load
directly proportional to message volume. The cheaper alternative is to rotate
**per epoch**, on the same cadence the content layer already re-keys on (group
membership changes, bans, or a time-based cadence) — this avoids a network
round trip per message, but leaves every message sent within one epoch linkable
to every other message from the same member during that epoch, only breaking the
link at epoch boundaries.

*Update: the per-message version of this fix has since been implemented
(`PresageTransport::send_as_rotating_phantom_device`) and is pending its first
confirmed test run.*
