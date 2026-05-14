# watching-zenoh Commercial License (LGPL-3.0 Alternative)

## Overview

This Commercial License provides an alternative to LGPL-3.0-or-later
for the watching-zenoh project (peer + client mode Zenoh-protocol
implementation, MVP = zenoh-pico parity). It is required when LGPL-3
obligations — source/object disclosure, anti-tivoization, or the
prohibition on private modifications — are unacceptable for your
distribution.

**Licensor:** newmassrael
**License Model:** GitHub Sponsors (Cumulative Sponsorship)
**License Version:** 1.0
**Copyright:** Copyright (c) 2026 newmassrael

---

## When Do You Need This Commercial License?

### You DON'T Need Commercial License If:

**Your project complies with LGPL-3 obligations:**

- Open source project under an LGPL-3-compatible license
- Internal use where you can provide the LGPL-3 §4 information for
  the watching-zenoh portion of your binary on request
- Embedded device where end users can rebuild and reinstall a modified
  watching-zenoh (anti-tivoization §4.e + §6 compliant — signing key
  provided, unlocked bootloader, documented relink procedure)
- Modifications to watching-zenoh source distributed under LGPL-3

**License: LGPL-3.0-or-later (FREE)**

### You NEED Commercial License If ANY of the following applies:

**1. Proprietary application (closed source) using watching-zenoh:**

- Your application's source code stays private
- You ship a binary that statically OR dynamically links
  watching-zenoh
- You do not want to provide LGPL-3 §4 object code / relink
  instructions

**2. Embedded firmware that locks out user modification:**

- Secure boot enforced, signed firmware, no user-installable updates
- Anti-tivoization (LGPL-3 §4.e) is unacceptable for your product's
  security or regulatory model

**3. Private modifications to watching-zenoh's own source:**

- You modify watching-zenoh internally and do not want to publish
  the changes
- You want to use modified watching-zenoh in proprietary contexts

**4. Redistribution as part of a derivative SDK:**

- You wrap watching-zenoh in a commercial SDK
- You rebrand watching-zenoh as a competing product (Zenoh-protocol
  library under your name)

**5. Avoiding LGPL-3 compliance overhead in general:**

- You want a clean proprietary license without any LGPL obligations

---

## What the Commercial License Grants (5-Way Exemption)

| # | Right granted | LGPL-3 (Free) | Commercial |
|---|---|---|---|
| 1 | Keep your application source closed | NO (must provide LGPL §4 info) | YES |
| 2 | Ship to locked-down devices (no anti-tivo) | NO (§4.e applies) | YES |
| 3 | Modify watching-zenoh source privately | NO (modifications LGPL-3) | YES |
| 4 | Redistribute watching-zenoh in a derivative SDK | NO | YES |
| 5 | Rebrand watching-zenoh as your own product | NO | YES |

All five rights are conveyed together — there is no à la carte
pricing for individual exemptions.

---

## Pricing (GitHub Sponsors Cumulative Model)

### Individual Developer License

- **Cumulative Sponsorship:** $5000 USD via GitHub Sponsors
- **For:** Individual developers, freelancers, small consultancies
- **Cumulative model:** Any combination of sponsorship tiers that
  totals $5000 USD over time grants the Individual License.

### Enterprise License (5+ developers)

- **Pricing:** Contact for quote (GitHub Sponsors available; volume
  pricing on request)
- **For:** Companies, organizations, government / regulated industry

**Sponsor at:** https://github.com/newmassrael
**Contact:** newmassrael@gmail.com

---

## Key Benefits vs LGPL-3.0 (Free)

| Aspect | LGPL-3.0 (Free) | Commercial |
|--------|-----------------|------------|
| Use unmodified watching-zenoh | YES (with §4 obligations) | YES |
| Static linking (proprietary app) | LGPL §4 disclosure required | NO disclosure required |
| Dynamic linking (proprietary app) | LGPL §4 disclosure required | NO disclosure required |
| Modify watching-zenoh source | Must publish modifications | Keep private |
| Embedded firmware (signed boot) | Anti-tivo §4.e applies | Anti-tivo waived |
| Redistribute as SDK / rebrand | Not permitted | Permitted |
| Support | Community (GitHub Issues) | Priority email |

---

## Terms

### License Grant

Upon receipt of the Commercial License fee (via cumulative GitHub
Sponsorship at the stated threshold or via Enterprise contract), the
Licensor grants the Licensee a non-exclusive, non-transferable,
worldwide license to use, modify, link, and distribute watching-zenoh
in proprietary products, subject to the following conditions.

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

If you fail to pay the cumulative threshold or breach the conditions
above, this Commercial License terminates automatically and your
watching-zenoh use reverts to LGPL-3.0 (with full §4 obligations
retroactively applicable to your distributed binaries).

### Warranty Disclaimer

watching-zenoh is provided "AS IS" without warranty of any kind. The
Licensor's total liability under this Commercial License is limited
to the fee paid.

---

## Relationship to Other Licenses

- **LGPL-3.0-or-later (this project's free option)**
  Open source use, with full LGPL-3 compliance.

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

    SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
    SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

---

## Contact

- **Email:** newmassrael@gmail.com
- **GitHub Sponsors:** https://github.com/newmassrael
- **GitHub Issues:** https://github.com/newmassrael/watching-zenoh/issues
