DRAFT — requires explicit SE/AE review before sending to customer.

# My Sigma-to-Omni pilot

Complete this as the migration owner with your delivery team. You may own several of the roles below; record who performs each review rather than assuming a separate administrator is required. Use your organization's approved storage. Leave unknown items blank; do not guess. **Never include passwords, API keys, tokens, personal data, or raw customer records.**

## People and scope

- Business goal:
- What a successful result would look like:
- Business reviewer:
- Technical operator:
- Sigma administrator:
- Security/privacy approver:
- Workbook name and approved reference:
- Workbook version/tag:
- Data model name and approved reference:
- Data model version:
- Organization/principal references:
- Secure credential reference—not its value:

## My preferred approach — select one; neither is the default

- [ ] Fully modeled: plan warehouse/dbt modeling work before Omni.
- [ ] Direct to Omni: reconstruct existing logic using existing warehouse data; no warehouse/dbt remodeling in this route.

This worksheet records intent only. Use `sigma-migrate route` and `sigma-migrate review` to record the actual local choice and review against the exact source and target mapping. Hashes and identity bindings are calculated automatically; this worksheet is not an approval file. If scope changes, import the new source and review again.

## What must be preserved?

- Key metrics, formulas, totals, and example expected answers:
- Important filters and time settings:
- People who must see the data:
- People who must not see the data:
- Controls, buttons/actions, and cross-page interactions:
- Data-entry/input tables (or confirmed absence):
- Saved views, scheduled deliveries, and embeds:
- Important layout/navigation:
- Anything that may be retired or redesigned, and who must approve it:

## Safe handling

- Approved location for source evidence and results:
- Who may access that location:
- Retention and deletion owner/policy:
- May these definitions be sent to the configured AI service? Pending / approved / not approved:
- Approval reference and approved scope (no secrets):
- Agreed call/spend limit for your run:

## Review log

| Item reviewed | Reviewer | Outcome / missing evidence | Approved reference, if applicable |
|---|---|---|---|
| Source scope and exact versions | | | |
| Migration approach | | | |
| Draft formulas and reuse plan | | | |
| Draft target design | | | |
| Independent validation plan | | | |
| Remaining implementation and acceptance work | | | |

Do not mark the migration accepted merely because planning or the offline example completes.
