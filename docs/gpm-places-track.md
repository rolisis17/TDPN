# GPM Places Track

Status: planning track (product direction + staged implementation)

Product idea:
- GPM starts as private access, but grows into a private network where useful places live.
- People should be able to use GPM like a VPN and also discover communities, pages, tools, projects, and creator spaces inside the mesh.
- The first goal is not to clone a social media feed. The first goal is to make GPM feel useful and inhabited.

## Why This Track Exists

Competing dVPNs mostly sell transport: private routes, residential exits, mixnet privacy, or node rewards.
GPM needs a sharper reason for people to join and stay.

The GPM Places direction adds that reason:
- cheaper private access
- internal pages and communities
- creator and project spaces
- direct support and capped credit rewards
- network contribution rewards for hosting, relaying, and safe operation

The product story becomes:

> GPM gives people private access, then gives them useful places to go inside the network.

## Product Layers

1. Private Access
   - stable VPN experience
   - current 2-hop default path
   - explicit privacy/performance profiles
   - public app remains simple

2. GPM Places
   - user profile pages
   - creator/project pages
   - community pages
   - static mini-sites
   - private web directory
   - internal search/discovery
   - report, block, and moderation primitives

3. Credits and Support
   - users can spend credits on access, retries, priority, or creator support
   - creators can receive direct support from users
   - early creator rewards are capped internal credits, not withdrawable currency
   - traffic/engagement rewards are delayed and fraud-checked

4. Community Graph
   - follows, memberships, subscriptions, comments, and community moderation come after GPM Places basics
   - discovery should begin curated and directory-based before any algorithmic feed

5. Marketplace and Apps
   - later track for tools, services, stores, and internal app surfaces hosted inside GPM
   - must inherit the same safety, moderation, fraud, and payment constraints as Places

## Non-Goals For The First Phase

- no public algorithmic feed
- no "go viral, earn tokens" launch messaging
- no cash payout for raw views
- no promise that credits are stake or withdrawable currency
- no anonymous monetized content without moderation controls
- no user-hosted public-exit obligation hidden behind content publishing
- no requirement that GPM internal content uses public internet exits

## Core Product Primitives

### GPM Place

A GPM Place is a registered internal destination such as:
- a profile page
- a creator page
- a project page
- a community page
- a static mini-site
- a tool page
- a documentation/library page

Potential address forms:
- `gpm://alice`
- `gpm://privacy-guides`
- `gpm://community/portugal`
- `gpm://creator/name`
- `gpm://tools/speed-test`

These are planning names only; production address format must be selected after routing, naming, moderation, and security review.

### Place Directory

The directory should expose:
- place id
- owner wallet or subject id
- content manifest hash/version
- moderation status
- visibility level
- category/tags
- safety labels
- hosting/mirror endpoints
- last verified timestamp

The directory must not become a raw browser-history log.

### Place Manifest

A manifest should describe:
- title and description
- owner identity
- content root or content hash
- allowed content type
- moderation labels
- update timestamp
- signature over manifest material

Manifest signing prevents silent content substitution by mirrors or relays.

Draft schema:
- `docs/schemas/gpm-place-manifest-v0.schema.json`

### Place Hosting

Initial implementation should prefer static content:
- HTML/CSS/assets
- markdown-rendered pages
- docs
- project pages
- simple community landing pages

Dynamic applications, comments, messaging, payments, and feeds should come later.

### Internal Routing

GPM internal content should avoid public exits when possible.

Target behavior:
- GPM app resolves a Place through the GPM directory.
- Client fetches content through mesh-internal routing or approved mirrors.
- Public internet exits are for normal internet access, not the default path for internal GPM Places.

This keeps internal content cheaper, lowers exit abuse exposure, and gives users a reason to stay inside the mesh.

## Credit and Incentive Model

Early incentives should be conservative.

Good first incentives:
- direct user support/tips
- curated grants for useful Places
- capped credits for verified hosting/mirroring uptime
- capped credits for useful documentation, guides, translations, and tools
- delayed referral credit only after referred users remain active

Signals that can help but must not directly pay raw rewards:
- page visits
- unique active users
- repeat visits
- saves/follows
- direct support volume
- report rate
- moderation status
- user retention after referral

Raw views are too easy to farm and should never be enough for payout.

## Abuse and Fraud Risks

Expected abuse:
- bot views
- click rings
- fake referrals
- AI spam pages
- copied or pirated content
- scam pages
- malware links
- adult/illegal content policy violations
- harassment communities
- reward farming
- exit operator liability confusion

Required controls before meaningful rewards:
- credit caps
- delayed rewards
- wallet/session/device eligibility checks
- user-level rate limits
- place-level rate limits
- report and takedown workflow
- quarantine state
- appeal workflow
- duplicate/stolen-content review
- content category policy
- manual curation for early discovery

## Moderation Model

Minimum states:
- `draft`
- `published`
- `limited`
- `quarantined`
- `removed`
- `appealed`

Moderation should be separate from VPN routing enforcement.

Admin Console owns:
- review queues
- takedown decisions
- place visibility changes
- reward holds
- credit voids
- abuse evidence review

Public GPM App owns:
- create/update own Place
- view own status
- report content
- block/mute content
- support a creator or Place

## Tier Interaction

Tier 0 Community Mode:
- can create limited Places after wallet/device checks
- can earn capped credits only
- cannot withdraw rewards
- content visibility and reward rates are conservative
- contribution/exit obligations must remain explicit and separate from publishing

Tier 1 Standard Access:
- can create basic Places
- can support creators/communities with credits
- can earn small capped creator credits if policy allows

Tier 2 Reliable Contributor:
- can earn higher capped credits
- can host/mirror Places when device and policy checks pass
- can participate in moderated community roles

Tier 3 Backbone Operator:
- can run higher-reliability hosting/mirror infrastructure
- may participate in curated directory, moderation, or marketplace infrastructure under policy

## Staged Roadmap

### P0: Product Shape

Deliverables:
- publish this track
- add public website language for "private access plus useful places"
- define first Place object and directory schema
- define credit safety rules for creators and hosts
- define moderation states and Admin Console boundary

Exit criteria:
- roadmap, website, and public/admin split agree on the same language
- no claim of public social feed or cash creator payout

### P1: Local Static Place Prototype

Deliverables:
- local-only Place manifest format
- signed static Place bundle
- local directory registration in dev mode
- portal mock/control for "My Place"
- static renderer or preview route

Exit criteria:
- one user can create a local static page
- another local client can resolve and view it through a controlled dev path
- manifest signature verification fails closed on tampering

### P2: Mesh-Internal Fetch Prototype

Deliverables:
- Place resolution through directory metadata
- internal fetch path that does not require public internet exit by default
- mirror/host descriptor format
- basic cache and freshness rules

Exit criteria:
- internal content can be retrieved through a mesh path
- stale or unsigned content is rejected or clearly labeled
- public exits are not required for the happy path

### P3: Credits and Direct Support

Deliverables:
- credit ledger model for support/tips
- capped creator support receipts
- no raw-view payout
- reward hold/void linkage in Admin Console

Exit criteria:
- user can support a Place with credits
- creator can see received support
- admin can hold/void disputed rewards

### P4: Discovery and Moderation

Deliverables:
- curated directory categories
- report/block flow
- Admin Console review queue
- quarantine/limited visibility states
- appeal record

Exit criteria:
- abusive Place can be reported, limited, removed, and appealed
- public app exposes no privileged moderation controls

### P5: Community Features

Deliverables:
- follows/subscriptions
- community membership
- comments or posts behind explicit moderation policy
- notification/read state

Exit criteria:
- communities feel useful without relying on an algorithmic feed
- moderation and abuse controls remain tractable

### P6: Larger Creator Economy

Deliverables:
- richer support models
- curated grants
- hosting/mirroring rewards
- possible limited cash-out policy after legal, fraud, tax, and compliance review

Exit criteria:
- reward fraud metrics are understood
- abuse response is staffed and documented
- legal/compliance review is complete before withdrawable payouts

## Implementation Guardrails

- VPN beta remains the foundation.
- Places must not block the stable 2-hop VPN launch.
- Internal content and creator rewards must not weaken exit-node safety.
- Credits start as network utility, not money.
- All creator rewards start capped and delayed.
- Public app can expose user-owned content controls only.
- Admin Console owns moderation, reward holds, credit voids, and abuse review.
- Avoid algorithmic feeds until moderation and fraud systems are proven.

## First Engineering Slice

Recommended first slice:
1. Define `PlaceManifest` schema in docs.
2. Add local-only signed static Place bundle generator.
3. Add local verifier for manifest signature and content hash.
4. Add a dev-only directory registration path.
5. Add a small portal "My Place" UI that is disabled unless the local runtime advertises Places support.

This creates a real prototype without committing to a full social network.
