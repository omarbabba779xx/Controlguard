# Live Validation Playbook

## Goal

This playbook documents how to prove the external IAM connectors in real environments.

The objective is to move `controlguard` from "advanced portfolio / pre-product" toward a more evidence-backed tool by validating:

- Microsoft Entra via Microsoft Graph
- Okta via the Okta Management API

## Expected outcome

For each live validation, capture:

- environment assumptions
- credentials model used
- exact command executed
- profile used
- sanitized output excerpt
- generated report artifact
- screenshot or exported HTML
- conclusion and limitations

## Required deliverables

Store them under a future `docs/validation-cases/` folder:

- `microsoft-entra-live-validation.md`
- `okta-live-validation.md`
- sanitized report JSON
- sanitized report HTML
- one screenshot per validation

## Microsoft Entra live validation

### Preconditions

- test tenant available
- application registration created
- `AuditLog.Read.All` application permission granted
- admin consent granted
- tenant licensed for authentication methods reporting

### Environment variables

```powershell
$env:CONTROLGUARD_GRAPH_TENANT_ID="..."
$env:CONTROLGUARD_GRAPH_CLIENT_ID="..."
$env:CONTROLGUARD_GRAPH_CLIENT_SECRET="..."
```

### Command

```powershell
controlguard scan --profile entra-admin-mfa --format html --output docs/validation-cases/entra-live-report.html
```

### Capture

- screenshot of the HTML report
- sanitized JSON excerpt
- count of compliant and non-compliant admins

## Okta live validation

### Preconditions

- test Okta org available
- OAuth service app or API token available
- scopes such as `okta.roles.read` and `okta.users.read`

### Environment variables

```powershell
$env:CONTROLGUARD_OKTA_ACCESS_TOKEN="..."
```

### Command

```powershell
controlguard scan --profile okta-admin-mfa --format html --output docs/validation-cases/okta-live-report.html
```

### Capture

- screenshot of the HTML report
- sanitized JSON excerpt
- count of admins with and without strong factors

## Documentation template

Each live validation note should answer:

1. What environment was used?
2. What assumptions were made?
3. What command was executed?
4. What report was generated?
5. What did the connector prove?
6. What remains unverified?
