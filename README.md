# openshift-vs-kubernetes-security

See the difference between OpenShift's secure-by-default pod admission (SCC + Pod Security Admission) and a DIY Kubernetes distribution that ships without a hardened operating system or built-in security baseline. Toggle both off and on against the same workload on a **lab** cluster, then turn bulletproof OpenShift security back on.

OpenShift is secure by default. That's the whole point. This is a learning aid, not a workaround. The real fix is making your workload pass `restricted-v2`.

## What OpenShift ships with that DIY Kubernetes doesn't

- **RHCOS**: an immutable, FIPS-capable, SELinux-enforced operating system tuned for containers
- **`restricted-v2` SCC**: secure pod-admission profile bound by default; non-root, no privileged escalation, dropped caps
- **PSA auto-sync**: Pod Security Admission labels reconciled from SCC, so the two layers stay aligned
- **Signed releases & image provenance**: every component built, signed, and tracked by Red Hat
- **Certified compliance**: FedRAMP, PCI-DSS, HIPAA, Common Criteria
- **Enterprise lifecycle**: predictable EUS streams, multi-year support, security errata

## Usage

```bash
oc login ...
./no-security.sh status            # current SCC+PSA state
./no-security.sh off               # relax SCC+PSA on existing namespaces (asks for confirmation)
./no-security.sh on                # restore SCC+PSA

./no-security.sh template-status   # project-request template wiring
./no-security.sh template-off      # install template → new namespaces born PSA privileged
./no-security.sh template-on       # remove template → new namespaces use default PSA restricted
```

Touches only user namespaces. Fully reversible. No data deleted.

## ⚠️ Lab clusters only

Never run on production, staging, or shared clusters.
