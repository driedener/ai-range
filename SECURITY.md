# Security

## This is an intentionally vulnerable lab

ai-range builds a deliberately insecure Active Directory environment and lets an AI agent attack it with real
offensive tools. Treat it like malware analysis infrastructure:

- Run the range on an **isolated network** (its own VLAN) that only reaches the controller, DNS and the internet
  as described in the [prerequisites](docs/prerequisites.md#range-network). Do not route it into production or
  home networks.
- **Never expose Kibana, Elasticsearch, Fleet or the Packer HTTP ports to the internet.** Restrict them with
  `scripts/controller/firewall.ps1` or `scripts/controller/firewall.sh`.
- Use **unique passwords** in `docker/.env` that you use nowhere else. The vulnerability profiles add
  well-known weak passwords on purpose (`ansible/playbooks/vars/vulns.yml`); never reuse them.
- Use a dedicated Proxmox API token and, if possible, a dedicated Proxmox cluster or node.
- Do not join the range to real identity providers or EDR tenants that protect production assets; use a
  separate SentinelOne site at minimum.
- Keep `docker/.env`, `range.yaml`, Terraform state and `agents/reports/` private. They contain credentials and
  details of your environment.

## Reporting a vulnerability

Vulnerabilities that are part of the lab design (the `vuln_*` profiles, the weak defaults of the range) are not
security issues.

If you find a real security problem in ai-range itself, for example a way for the Red agent to escape its scope,
for an agent to read data it should not (such as the ground truth), or a leak of secrets, please report it
**privately** through GitHub's "Report a vulnerability" function (Security tab of the repository) instead of
opening a public issue. Include steps to reproduce and the affected version or commit.
