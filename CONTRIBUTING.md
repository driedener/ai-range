# Contributing

Contributions are welcome: bug reports, documentation fixes, new scenarios, vulnerability profiles, detection
improvements and support for further platforms.

## Before you start

- Read the documentation in [`docs/`](docs/index.md), in particular [Reference](docs/conventions.md) for the
  conventions every component follows.
- For larger changes, open an issue first to discuss the approach.
- Report security problems privately, see [SECURITY.md](SECURITY.md).

## Guidelines

- **No hard-coded hosts or IPs.** Everything topology-related comes from `range.yaml`: Ansible uses inventory
  groups and `range_*` variables, the agents use `agents/airange/topology.py`, Terraform and Packer read
  `range.yaml`.
- **No secrets in the repository.** Read them from the environment (`docker/.env`). Do not commit `range.yaml`,
  `docker/.env`, generated files, vendor installers or API specifications.
- **Idempotent automation.** Playbooks and roles must be safe to re-run.
- **Vulnerabilities only as opt-in profiles.** New intentional weaknesses go into a `vuln_*` role and a tag in
  `ansible/playbooks/vulns.yml`, never into `site.yml`. Document them in `docs/vulnerability-profiles.md`.
- **Agents keep least privilege.** New agent capabilities are MCP tools with explicit scope checks, not generic
  shell or API access.
- English for code, comments and documentation.
- Update the documentation in `docs/` together with the code. Check the site builds:
  `pip install zensical && zensical build`.

## Pull requests

Keep pull requests focused, describe what you changed and how you tested it (which playbooks, scenarios or
smoke tests in `agents/tests/` you ran), and mention changes to `range.yaml` keys or `docker/.env` variables.

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
