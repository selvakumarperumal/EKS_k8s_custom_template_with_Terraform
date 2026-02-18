# Cost Optimization Guide

This document explains how to minimize AWS costs when using this EKS template.
All paid monitoring/logging services are **disabled by default** — you can enable them
individually or use the recommended kube-native alternatives.

---

## Optional Paid Services

| Service | Variable | Default | Monthly Cost (est.) |
|---------|----------|---------|---------------------|
| CloudWatch Logging | `enable_cluster_logging` | `false` | ~$5–10 |
| VPC Flow Logs | `enable_vpc_flow_logs` | `false` | ~$5 |
| EC2 Detailed Monitoring | `enable_detailed_monitoring` | `false` | ~$2/instance |
| GuardDuty | `enable_guardduty` | `false` | ~$4–15 |
| AWS Config | `enable_aws_config` | `false` | ~$2–5 |

> [!TIP]
> With all optional services disabled, you only pay for the core EKS cluster ($0.10/hr),
> EC2 instances, NAT Gateway (~$33/mo), and data transfer.

### Enabling a Service

In `terraform.tfvars`:

```hcl
# Enable only what you need:
enable_cluster_logging    = true   # CloudWatch control plane logs
enable_vpc_flow_logs      = true   # Network traffic logs
enable_detailed_monitoring = true  # 1-minute EC2 metrics
enable_guardduty          = true   # Threat detection
enable_aws_config         = true   # Compliance rules
```

---

## Kube-Native Alternatives

These open-source tools run inside your cluster and replace the paid AWS services at
zero additional AWS cost (you only pay for the compute they consume).

### Monitoring: Prometheus + Grafana
**Replaces:** CloudWatch Metrics, Detailed Monitoring

```bash
# Install via Helm
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --set prometheus.prometheusSpec.retention=7d
```

**What you get:**
- Node, pod, and container metrics (CPU, memory, disk, network)
- Pre-built Grafana dashboards for Kubernetes
- Alerting via Alertmanager (Slack, PagerDuty, email)
- 15-second scrape intervals (better than CloudWatch's 1-minute)

### Logging: ELK Stack or Loki
**Replaces:** CloudWatch Logs, EKS Control Plane Logging

**Option A — Loki (lightweight):**
```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm install loki grafana/loki-stack \
  --namespace logging --create-namespace \
  --set fluent-bit.enabled=true \
  --set grafana.enabled=false  # Use existing Grafana from monitoring stack
```

**Option B — ELK Stack (full-featured):**
```bash
helm repo add elastic https://helm.elastic.co
helm install elasticsearch elastic/elasticsearch --namespace logging --create-namespace
helm install kibana elastic/kibana --namespace logging
helm install filebeat elastic/filebeat --namespace logging
```

### Network Observability: Cilium Hubble
**Replaces:** VPC Flow Logs

```bash
# If using Cilium CNI:
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true
```

**What you get:**
- Real-time network flow visibility
- DNS-aware flow logs
- Service dependency maps
- HTTP/gRPC-level observability

### Runtime Security: Falco
**Replaces:** GuardDuty (for container-level threats)

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set falcosidekick.enabled=true
```

**What you get:**
- Runtime syscall monitoring
- Detection of shell spawning, file access, network connections
- Custom rules for your workloads
- Alerting via Slack, PagerDuty, or SIEM

### Policy Enforcement: Kyverno or OPA/Gatekeeper
**Replaces:** AWS Config rules (for Kubernetes resources)

```bash
# Kyverno (recommended — simpler)
helm repo add kyverno https://kyverno.github.io/kyverno
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace
helm install kyverno-policies kyverno/kyverno-policies --namespace kyverno
```

**What you get:**
- Policy-as-code for Kubernetes resources
- Enforce security baselines (no privileged pods, required labels, etc.)
- Mutating webhooks (auto-add security contexts, resource limits)
- Audit mode for gradual policy rollout

---

## Cost Comparison

| Category | AWS Service | Cost/mo | Kube-Native | Cost/mo |
|----------|------------|---------|-------------|---------|
| Metrics | CloudWatch Detailed | ~$6–12 | Prometheus + Grafana | $0* |
| Logging | CloudWatch Logs | ~$5–10 | Loki or ELK | $0* |
| Network | VPC Flow Logs | ~$5 | Cilium Hubble | $0* |
| Security | GuardDuty | ~$4–15 | Falco | $0* |
| Compliance | AWS Config | ~$2–5 | Kyverno | $0* |
| **Total** | | **~$22–47** | | **$0*** |

> \* Kube-native tools consume node resources (CPU/memory). On a cluster that's
> already running, the marginal cost is typically negligible. Budget ~0.5 vCPU
> and ~1 GiB RAM for the full monitoring stack.

---

## Always-On Costs (cannot be disabled)

These are fundamental EKS costs that apply regardless of toggles:

| Resource | Cost |
|----------|------|
| EKS Control Plane | $0.10/hr (~$73/mo) |
| NAT Gateway | $0.045/hr (~$33/mo) + data |
| EC2 Instances (t3.medium × 2) | ~$61/mo |
| EBS Volumes (20 GiB gp3 × 2) | ~$3.20/mo |
| **Minimum Total** | **~$170/mo** |

> [!IMPORTANT]
> Use **Spot instances** for non-critical workloads to save 60–90% on compute.
> This template includes a spot node group by default.
