# Skill: IaC Management & DevOps Automation

## When to Use
Use this skill when deploying new infrastructure components, updating environment configurations, or performing cloud resource audits.

## Core Knowledge
- **Tools**: Terraform (State, Providers), Ansible (Playbooks, Roles).
- **Security by Design**: 
  - Least Privilege Access (IAM)
  - Encryption at rest and in transit
  - Public/Private subnet isolation
- **State Management**: Always use remote state (S3/GCS/Consul) for collaborative environments.

## Deployment Patterns
1. **Terraform Apply**:
   - `terraform plan -out=plan.out`
   - Review plan for destructive changes.
   - `terraform apply plan.out`
2. **Ansible Hardening**:
   - Apply OS hardening roles (e.g., CIS benchmarks).
   - Update security patches via `apt`/`yum`.

## Validation
1. Use `socroot-development` MCP to run compliance scans on the new infrastructure.
2. Verify that all resources are tagged with `Owner`, `Project`, and `Environment`.
