# watching-zenoh Commercial License (AGPL-3.0 Alternative)

## Overview

This Commercial License provides an alternative to AGPL-3.0-or-later
for the watching-zenoh project (peer + client mode Zenoh-protocol
implementation, MVP = zenoh-pico parity). It is required when AGPL-3
obligations — whole-work copyleft on anything you convey, the §13
network-interaction source offer, anti-tivoization, or the prohibition
on private modifications — are unacceptable for your product.

**Licensor:** newmassrael
**License Model:** Negotiated; contact the Licensor
**License Version:** 2.0 (supersedes the LGPL-era 1.0)
**Copyright:** Copyright (c) 2026 newmassrael

---

## When Do You Need This Commercial License?

### You DON'T Need Commercial License If:

**Your project complies with AGPL-3 obligations:**

- Open source project under an AGPL-3-compatible license
- Purely internal use: you neither convey the work to anyone nor let
  anyone interact with a MODIFIED version over a network
- Embedded device where end users can rebuild and reinstall a modified
  watching-zenoh (anti-tivoization §6 compliant — signing key
  provided, unlocked bootloader, documented install procedure)
- Modifications to watching-zenoh source distributed under AGPL-3, and
  offered as Corresponding Source to remote users per §13

**License: AGPL-3.0-or-later (FREE)**

### You NEED Commercial License If ANY of the following applies:

**1. Proprietary application (closed source) using watching-zenoh:**

- Your application's source code stays private
- You ship a binary that statically OR dynamically links
  watching-zenoh
- Note what changed from the LGPL era: under AGPL-3 there is no
  "provide relink information and keep your own source closed"
  option. Linking makes the combined work a covered work, and
  dynamic linking does not avoid it.

**2. Network service built on a modified watching-zenoh (AGPL-3 §13):**

- You run a modified watching-zenoh behind an API, broker, router, or
  hosted product, and users interact with it over a network
- You do not want to offer those users the Corresponding Source of
  your modified version
- This trigger has no LGPL-era equivalent. It is the clause that makes
  "we only operate it, we never ship it" stop being a way around the
  free tier.

**3. Embedded firmware that locks out user modification:**

- Secure boot enforced, signed firmware, no user-installable updates
- Anti-tivoization (AGPL-3 §6 Installation Information) is
  unacceptable for your product's security or regulatory model

**4. Private modifications to watching-zenoh's own source:**

- You modify watching-zenoh internally and then convey or serve the
  result, and do not want to publish the changes

**5. Redistribution as part of a derivative SDK:**

- You wrap watching-zenoh in a commercial SDK
- You rebrand watching-zenoh as a competing product (Zenoh-protocol
  library under your name)

**6. Avoiding AGPL-3 compliance overhead in general:**

- You want a clean proprietary license without any AGPL obligations

---

## What the Commercial License Grants (6-Way Exemption)

| # | Right granted | AGPL-3 (Free) | Commercial |
|---|---|---|---|
| 1 | Keep your application source closed | NO (whole work is covered) | YES |
| 2 | Operate a modified version as a network service without publishing it | NO (§13 source offer) | YES |
| 3 | Ship to locked-down devices (no anti-tivo) | NO (§6 applies) | YES |
| 4 | Modify watching-zenoh source privately | NO (modifications AGPL-3) | YES |
| 5 | Redistribute watching-zenoh in a derivative SDK | NO | YES |
| 6 | Rebrand watching-zenoh as your own product | NO | YES |

All six rights are conveyed together — there is no à la carte
pricing for individual exemptions.

---

## Pricing

Pricing is not published. Terms depend on team size, product, and
distribution model — including which of the six exemptions above you
actually need — so a figure quoted out of that context would be
misleading in both directions.

**Contact the Licensor for a quote.** GitHub Sponsors is available as
a payment route once terms are agreed.

- **Individual Developer License** — individual developers,
  freelancers, small consultancies
- **Enterprise License (5+ developers)** — companies, organizations,
  government / regulated industry

**Sponsor at:** https://github.com/newmassrael
**Contact:** newmassrael@gmail.com

---

## Key Benefits vs AGPL-3.0 (Free)

| Aspect | AGPL-3.0 (Free) | Commercial |
|--------|-----------------|------------|
| Use unmodified watching-zenoh, privately | YES | YES |
| Static linking (proprietary app) | Combined work must be AGPL-3 | NO disclosure required |
| Dynamic linking (proprietary app) | Combined work must be AGPL-3 | NO disclosure required |
| Modify watching-zenoh source | Must publish modifications | Keep private |
| Serve a modified version over a network | §13 source offer required | §13 waived |
| Embedded firmware (signed boot) | Anti-tivo §6 applies | Anti-tivo waived |
| Redistribute as SDK / rebrand | Not permitted | Permitted |
| Support | Community (GitHub Issues) | Priority email |

---

## Terms

### License Grant

Upon receipt of the Commercial License fee agreed with the Licensor,
the Licensor grants the Licensee a non-exclusive, non-transferable,
worldwide license to use, modify, link, distribute, and operate as a
network service watching-zenoh in proprietary products, subject to the
following conditions.

### Conditions

1. **License preservation in your own products.** You must preserve
   the watching-zenoh copyright notice in your product's
   documentation or About screen ("This product includes
   watching-zenoh, Copyright (c) 2026 newmassrael").
2. **No sublicensing of watching-zenoh itself.** You may sublicense
   your derivative products to your customers, but you may not
   sublicense watching-zenoh standalone (rebrand and sell raw
   watching-zenoh as a standalone library to a third party).
3. **SCE runtime engine is separate.** This Commercial License does
   NOT grant any rights to SCE's runtime engine, which is
   independently licensed by SCE. Your `out/` artifacts depend on
   SCE; obtain SCE's licensing separately at
   https://github.com/newmassrael/scxml-core-engine.

### Termination

If you fail to pay the agreed fee or breach the conditions
above, this Commercial License terminates automatically and your
watching-zenoh use reverts to AGPL-3.0-or-later, with the full
whole-work copyleft and §13 network-source obligations applying to
what you distribute or operate from that point.

### Warranty Disclaimer

watching-zenoh is provided "AS IS" without warranty of any kind. The
Licensor's total liability under this Commercial License is limited
to the fee paid.

---

## Relationship to Other Licenses

- **AGPL-3.0-or-later (this project's free option)**
  Open source use, with full AGPL-3 compliance including §13.

- **LGPL-3.0-or-later (this project's former free option)**
  Revisions published before the AGPL change offered the free tier as
  LGPL-3.0-or-later, with this same commercial alternative. Those
  grants remain valid for the copies they were given with; they do not
  extend to this revision or later ones.

- **MIT (generated code)**
  Code emitted by `sce-codegen` from watching-zenoh's SCXML sources is
  MIT-licensed (per SCE's `LICENSE-GENERATED.md`). The author of the
  input SCXML file owns the copyright. For watching-zenoh's own
  `sources/`, copyright belongs to newmassrael.

- **SCE runtime engine (LGPL-2.1 + Static-Linking-Exception OR
  SCE Commercial)**
  Separately licensed by SCE. Required at runtime by all
  watching-zenoh `out/` artifacts. A watching-zenoh Commercial License
  does NOT include SCE Commercial.

- **Zenoh / zenoh-pico (Apache-2.0 OR EPL-2.0)**
  Independent projects. watching-zenoh is a wire-protocol-compatible
  reimplementation; no code is shared. Interop only.

---

## SPDX Identifier

Files covered by this Commercial License (when chosen by the
Licensee) use:

    SPDX-License-Identifier: LicenseRef-watching-zenoh-Commercial
    SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

Files dual-licensed (most of the watching-zenoh source) use:

    SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
    SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

---

## Contact

- **Email:** newmassrael@gmail.com
- **GitHub Sponsors:** https://github.com/newmassrael
- **GitHub Issues:** https://github.com/newmassrael/watching-zenoh/issues
