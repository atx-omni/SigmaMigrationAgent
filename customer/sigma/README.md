DRAFT — requires explicit SE/AE review before sending to customer.

# Sigma-to-Omni pilot kit

Start by opening **START-HERE.html** in your browser. It is a local, printable guide; it does not connect to your accounts.

This guide is for migration teams who own their source and destination platforms. It assumes you have the access to set up and operate the tool yourself; no AI engineering background is required. Follow the numbered installation, credential, capture, and operating steps directly.

- **START-HERE.html:** complete, printable setup and operating page with copy-and-paste commands, both migration choices, expected results, and troubleshooting.
- **start.py:** offline setup check and guided demonstration; no live accounts or AI calls.
- **PILOT-WORKSHEET.md:** decisions and information to gather, without passwords or keys.
- **SETUP-AND-USAGE.md:** editable text version of the same instruction page, with guided setup, review, build, validation and export.
- **engine/:** the supplied Python software, software license, and historical upstream attribution.
- **contracts/:** technical input definitions and fictional reference examples.
- **PACKAGE-MANIFEST.json:** exact file fingerprints and source snapshot status.
- **.agents/skills/sigma-to-omni-migration/:** optional current agent skill, with the
  same instructions as the repository and a matching runtime-version requirement.

Extract this ZIP once. There is no nested skill ZIP, mandatory plugin installation,
or Claude/Codex subscription requirement for the offline example. The optional
skill is already included as a folder; see step 13 of the guide to use it. Do not
merge this package with an older migration package.

Use the Sigma steps in this guide. Some shared data types retain historical names, but no Domo source adapter or Domo operator command is available in this distribution.

Keep the original ZIP unchanged. Confirm its publisher through your trusted release channel before installation; its own checksums do not authenticate it. Follow setup to keep real evidence in a separate private workspace. The default export is only a minimal support summary; full confidential evidence requires the explicit migration export purpose and sharing review. Do not send the whole working folder to support or another customer.

This is a supervised local pre-push pilot. The supported route generates actual model and dashboard artifacts; unsupported source behavior remains blocked. No live target deployment or migration acceptance is claimed. Use the guide's `sigma-migrate` workflow, not the legacy extraction-only `start.py`, for review and package generation.
