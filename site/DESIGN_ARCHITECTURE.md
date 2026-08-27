# KernAid public-site experience architecture

The public site has two deliberately separate commercial experiences. They
share the KernAid identity and product truth, but not their information density,
visual language or conversion path.

## Experience map

| Route | Audience | First question answered | Primary outcome |
| --- | --- | --- | --- |
| `/` | Home users and very small offices | “Can this help when my PC stops working?” | Understand the three-step Rescue journey and the planned single-use offer |
| `/enterprise/` | CIOs, IT leaders, MSP owners and service-desk managers | “Can this make recovery governed and repeatable?” | Evaluate the platform, trust boundary and Design Partner model |
| `/private/` | Authorized internal operators | “Which exact artifact may I download?” | Verify provenance and download the promoted candidate |

## Retail experience

- Reading level: plain, short Italian; one idea per block.
- Emotional sequence: alarm → reassurance → simple action → transparent limit.
- Product story: insert the future KernAid device, follow the guided diagnosis,
  review the proposed next step.
- Commercial object: a planned `€29,99` single-use intervention, clearly marked
  as launch pricing and not yet for sale.
- Visual system: warm light surfaces, oversized friendly typography, soft
  geometry and a code-native PC/device illustration.
- Forbidden: enterprise acronyms, raw architecture diagrams, fake testimonials,
  success percentages, universal repair claims or a live purchase CTA.

## Enterprise experience

- Reading level: concise executive language backed by technical specifics.
- Decision sequence: downtime exposure → operating model → platform boundary →
  deployment paths → commercial model → qualification status.
- Product story: Desk and Rescue feed the same evidence, policy and audit model;
  Fleet is the planned governance layer.
- Commercial object: planned Design Partner access from `$299/month`, visibly
  separated from general availability.
- Visual system: graphite surfaces, precise grids, instrument-like data views,
  restrained lime/cyan signals and editorial typography.
- Forbidden: “supports every machine” as a current claim, completed Fleet or
  repair-pack claims, hidden provider costs, fake compliance certifications or
  unsupported ROI numbers.

## Shared truth contract

Both experiences must make these facts reachable without ambiguity:

1. the current public path is a diagnosis-only engineering preview;
2. production repairs, physical USB qualification and Secure Boot remain open;
3. the provider is optional and never receives a privileged raw shell;
4. AI accounts and usage remain the customer's responsibility;
5. only the authenticated private area distributes a catalog-authorized ISO;
6. current status and security documentation remain publicly linked.

Retail and Enterprise use separate HTML and CSS files. `styles.css` remains the
private-distribution stylesheet so commercial redesigns cannot accidentally
weaken or visually couple the authenticated artifact workflow.
