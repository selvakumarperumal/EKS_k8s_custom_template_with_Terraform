<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Module — Build Steps</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/dracula.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box }
    body { background: #282a36; color: #f8f8f2; font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.7; padding: 2rem }
    .container { max-width: 1000px; margin: 0 auto }
    h1 { color: #bd93f9; font-size: 2.2rem; text-align: center; margin-bottom: .5rem; animation: glow 2s ease-in-out infinite alternate }
    @keyframes glow { from { text-shadow: 0 0 5px #bd93f9 } to { text-shadow: 0 0 20px #bd93f9, 0 0 40px #bd93f966 } }
    .subtitle { color: #6272a4; text-align: center; margin-bottom: 3rem; font-size: 1.1rem }
    .progress-bar { position: fixed; top: 0; left: 0; height: 3px; background: linear-gradient(90deg, #bd93f9, #ff79c6, #50fa7b); z-index: 999; transition: width .3s }
    .phase { margin: 3rem 0; padding: 1.5rem; border-left: 4px solid #bd93f9; background: #1e1f29; border-radius: 0 8px 8px 0; opacity: 0; transform: translateY(30px); transition: all .6s ease }
    .phase.visible { opacity: 1; transform: translateY(0) }
    .phase h2 { color: #ff79c6; font-size: 1.5rem; margin-bottom: 1rem }
    .step { margin: 2rem 0; padding: 1.5rem; background: #44475a; border-radius: 8px; border: 1px solid #6272a4; opacity: 0; transform: translateX(-20px); transition: all .5s ease }
    .step.visible { opacity: 1; transform: translateX(0) }
    .step:hover { border-color: #bd93f9; box-shadow: 0 0 15px #bd93f933 }
    .step h3 { color: #50fa7b; font-size: 1.2rem; margin-bottom: .8rem }
    .step h3 span { color: #6272a4; font-size: .9rem; font-weight: normal }
    .step .note { color: #f1fa8c; font-size: .9rem; margin-top: .8rem; padding: .5rem .8rem; background: #282a36; border-radius: 4px; border-left: 3px solid #f1fa8c }
    .step .explain { color: #f8f8f2; font-size: .9rem; margin-top: .8rem; padding: .8rem; background: #1e1f29; border-radius: 6px; border-left: 3px solid #8be9fd; line-height: 1.6 }
    .step .explain strong { color: #ff79c6 }
    .step .explain code { background: #44475a; padding: 1px 5px; border-radius: 3px; font-size: .85rem }
    pre { background: #282a36 !important; border-radius: 6px; padding: 1rem !important; margin: .8rem 0; overflow-x: auto; border: 1px solid #6272a4 }
    code { font-family: 'Fira Code', 'Consolas', monospace; font-size: .85rem }
    .d2-diagram { margin: 1rem 0; min-height: 100px; display: flex; justify-content: center; align-items: center; background: #282a36; border-radius: 8px; padding: 1rem; border: 1px solid #6272a4; transition: all .8s ease }
    .d2-diagram.loaded { animation: diagramFadeIn .8s ease }
    @keyframes diagramFadeIn { from { opacity: 0; transform: scale(.95) translateY(10px) } to { opacity: 1; transform: scale(1) translateY(0) } }
    .d2-diagram.loading { color: #6272a4; font-style: italic }
    .d2-diagram svg { max-width: 100%; height: auto; transition: transform .4s ease }
    .d2-diagram:hover svg { transform: scale(1.02) translateY(-3px); filter: drop-shadow(0 8px 20px #bd93f933) }
    @keyframes flowData { to { stroke-dashoffset: -16 } }
    .d2-diagram svg path[fill="none"][stroke]:not([stroke="none"]) { stroke-dasharray: 8 8 !important; animation: flowData 0.8s linear infinite }
    .d2-diagram svg g { transform-origin: center; transition: transform 0.2s ease, filter 0.2s ease }
    .d2-diagram svg g:hover { filter: drop-shadow(0 0 8px #bd93f988) }
    .d2-diagram:hover { border-color: #ff79c6; box-shadow: 0 0 20px #ff79c622 }
    .summary { margin: 3rem 0; opacity: 0; transform: translateY(30px); transition: all .6s ease }
    .summary.visible { opacity: 1; transform: translateY(0) }
    .summary table { width: 100%; border-collapse: collapse; font-size: .9rem }
    .summary th { background: #bd93f9; color: #282a36; padding: .6rem; text-align: left }
    .summary td { padding: .5rem .6rem; border-bottom: 1px solid #44475a; transition: background .3s }
    .summary tr:hover { background: #44475a }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .75rem; font-weight: bold }
    .badge-gd { background: #ff5555; color: #f8f8f2 }
    .badge-cfg { background: #bd93f9; color: #282a36 }
    .var-table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: 1rem 0 }
    .var-table th { background: #6272a4; color: #f8f8f2; padding: .5rem .6rem; text-align: left }
    .var-table td { padding: .4rem .6rem; border-bottom: 1px solid #44475a; color: #f8f8f2 }
    .var-table tr:hover { background: #44475a }
    .var-table code { background: #282a36; padding: 1px 5px; border-radius: 3px; font-size: .8rem; color: #50fa7b }
    .step-number { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: #bd93f9; color: #282a36; font-weight: bold; font-size: .8rem; margin-right: 8px }
  </style>
</head>

<body>
  <div class="container">
    <div class="progress-bar" id="progressBar"></div>
    <h1>🛡️ Security Module</h1>
    <p class="subtitle">Continuous threat detection and compliance monitoring — GuardDuty + AWS Config</p>

    <div class="explain"
      style="margin-bottom: 3rem; background: #1e1f29; padding: 1.5rem; border-left: 4px solid #bd93f9; border-radius: 8px;">
      <h3 style="color: #bd93f9; margin-bottom: 0.5rem;">🛡️ Module Overview</h3>
      This module wraps the entire infrastructure in a <strong>continuous security monitoring perimeter</strong> using two AWS services:
      <ul style="margin-left: 1.5rem; margin-top: 0.5rem; color: #f8f8f2;">
        <li><strong>Amazon GuardDuty:</strong> ML-based threat detection — analyzes VPC Flow Logs, CloudTrail, DNS logs, and EKS audit logs to detect crypto mining, credential theft, privilege escalation, and more</li>
        <li><strong>AWS Config:</strong> Configuration compliance — continuously snapshots resource state and evaluates it against security rules (Is logging enabled? Is the API private? Are secrets encrypted?)</li>
      </ul>
      <div style="margin-top: 0.8rem; padding: 0.5rem 0.8rem; background: #282a36; border-radius: 4px; border-left: 3px solid #f1fa8c; color: #f1fa8c; font-size: 0.9rem;">
        💡 <strong>Defense in Depth:</strong> GuardDuty detects active threats. Config catches misconfigurations. Together they cover both runtime attacks and configuration drift.
      </div>
      <em style="color: #6272a4; display: block; margin-top: 0.5rem;">📂 Source: <code>modules/security/main.tf</code> · <code>variables.tf</code> · <code>outputs.tf</code> · Cost: ~$10-30/month</em>
    </div>

    <div id="content"></div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📥 Input Variables</h2>
      <table class="var-table">
        <thead><tr><th>Variable</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>cluster_name</code></td><td><code>string</code></td><td>—</td><td>Name of the EKS cluster (used for resource naming)</td></tr>
          <tr><td><code>enable_guardduty</code></td><td><code>bool</code></td><td><code>true</code></td><td>Enable Amazon GuardDuty for threat detection</td></tr>
          <tr><td><code>enable_config</code></td><td><code>bool</code></td><td><code>true</code></td><td>Enable AWS Config for configuration compliance</td></tr>
          <tr><td><code>tags</code></td><td><code>map(string)</code></td><td><code>{}</code></td><td>Tags to apply to all resources</td></tr>
        </tbody>
      </table>
    </div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📤 Outputs</h2>
      <table class="var-table">
        <thead><tr><th>Output</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>guardduty_detector_id</code></td><td>ID of the GuardDuty detector (empty if disabled)</td></tr>
          <tr><td><code>config_recorder_id</code></td><td>ID of the AWS Config configuration recorder (empty if disabled)</td></tr>
        </tbody>
      </table>
    </div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">Build Summary</h2>
      <table>
        <thead><tr><th>Step</th><th>Resource</th><th>Category</th><th>Time</th></tr></thead>
        <tbody id="summary-table"></tbody>
      </table>
    </div>
  </div>

  <script>
    const STEPS = [
      {
        phase: "GuardDuty — Intelligent Threat Detection", steps: [
          {
            title: "Enable GuardDuty Detector", cat: "gd", time: "~15s",
            hcl: `resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true   # Activate immediately — starts analyzing data

  finding_publishing_frequency = "FIFTEEN_MINUTES"  # How often findings are updated

  tags = var.tags
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
sources: "📊 Data Sources" {
  style.fill: "#1e1f29"; style.stroke: "#6272a4"
  vfl: "VPC Flow Logs" { shape: document; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  ct: "CloudTrail Events" { shape: document; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  dns: "Route 53 DNS Logs" { shape: document; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
}
gd: "🛡️ AWS GuardDuty" {
  style.fill: "#282a36"; style.stroke: "#bd93f9"; style.stroke-width: 2
  det: "🧠 ML Detector\\n(Updates every 15 min)" { shape: hexagon; style.fill: "#bd93f9"; style.font-color: "#282a36" }
}
alert: "🚨 Security Findings" { shape: callout; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
sources.vfl -> gd.det: "Analyzes" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
sources.ct -> gd.det { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
sources.dns -> gd.det { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
gd.det -> alert: "Generates Alerts" { style.stroke: "#ff5555"; style.stroke-dash: 5; style.stroke-width: 2 }`,
            note: "Detects crypto mining, compromised creds, unauthorized API calls, privilege escalation.",
            explain: "GuardDuty uses <strong>machine learning</strong>, <strong>anomaly detection</strong>, and <strong>threat intelligence feeds</strong> to identify threats. It automatically analyzes VPC Flow Logs, CloudTrail, and DNS queries — no agent installation required. <code>finding_publishing_frequency = FIFTEEN_MINUTES</code> means findings are updated every 15 minutes. Cost is based on data volume (~$5-15/mo for small clusters)."
          },
          {
            title: "Enable EKS Audit Log Analysis", cat: "gd", time: "~5s",
            hcl: `resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
eks: "⬡ EKS Cluster" {
  style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
  audit: "📝 K8s Audit Logs\\n(API Server Events)" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
gd: "🛡️ GuardDuty" { shape: hexagon; style.fill: "#bd93f9"; style.font-color: "#282a36" }
threats: "⚠️ Detected Threats" {
  style.fill: "#282a36"; style.stroke: "#ff5555"
  t1: "Unauthorized kubectl exec" { shape: rectangle; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  t2: "Privileged containers" { shape: rectangle; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  t3: "Anomalous API calls" { shape: rectangle; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
}
eks.audit -> gd: "Stream Audit Logs" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
gd -> threats: "K8s-Specific Findings" { style.stroke: "#ff5555"; style.stroke-dash: 5 }`,
            note: "Uses the modern aws_guardduty_detector_feature resource (replaces deprecated datasources block).",
            explain: "When enabled, GuardDuty analyzes Kubernetes API audit logs to detect: <strong>unauthorized kubectl exec</strong> into pods, <strong>privileged container creation</strong>, <strong>anomalous API calls</strong> at unusual times, access from <strong>known malicious IPs</strong>, and <strong>credential exfiltration attempts</strong>."
          },
          {
            title: "Enable EBS Malware Protection", cat: "gd", time: "~5s",
            hcl: `resource "aws_guardduty_detector_feature" "ebs_malware" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
finding: "🚨 GuardDuty Finding\\n(Suspicious Activity)" { shape: callout; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
scan: "🔍 Malware Scanner\\n(On-demand)" { shape: hexagon; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
ebs: "💾 EBS Volumes\\n(Node Root Disks)" { shape: cylinder; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
finding -> scan: "Triggers Scan" { style.stroke: "#ff5555"; style.stroke-dash: 5 }
scan -> ebs: "Scans Volume Snapshot" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }`,
            note: "Scans ONLY when triggered by a finding — no performance impact during normal operation.",
            explain: "GuardDuty can scan EBS volumes attached to EKS nodes for <strong>malware</strong> when it detects suspicious activity. This runs <strong>only when triggered</strong> by a finding (not continuously), so it has no impact on normal performance. It creates a snapshot, scans it in an isolated environment, and reports findings."
          },
        ]
      },
      {
        phase: "AWS Config — Configuration Compliance", steps: [
          {
            title: "Create Config Recorder + IAM Role", cat: "cfg", time: "~15s",
            hcl: `resource "aws_iam_role" "config" {
  count       = var.enable_config ? 1 : 0
  name_prefix = "\${var.cluster_name}-config-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole"; Effect = "Allow"
      Principal = { Service = "config.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
  role       = aws_iam_role.config[0].name
}

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_config ? 1 : 0
  name     = "\${var.cluster_name}-config-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group { all_supported = true }
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
config: "⚙️ AWS Config" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  recorder: "📸 Configuration Recorder\\n(Snapshots all resources)" { shape: cylinder; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  role: "🔐 IAM Role\\n(config.amazonaws.com)" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
resources: "☁️ AWS Resources\\n(EKS, VPC, IAM, ...)" { shape: cloud; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
resources -> config.recorder: "Config Changes" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
config.role -> config.recorder: "Read Access" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }`,
            note: "all_supported = true records ALL resource types — any config change is tracked.",
            explain: "The Config Recorder <strong>continuously snapshots</strong> the configuration state of all AWS resources. It needs an IAM role with <code>AWS_ConfigRole</code> to read resource configurations. Every time a resource changes (SG rule added, tag modified, etc.), Config records the before and after state."
          },
          {
            title: "Create EKS Compliance Rules", cat: "cfg", time: "~15s",
            hcl: `# Rule 1: Is EKS control plane logging enabled?
resource "aws_config_config_rule" "eks_cluster_logging" {
  count = var.enable_config ? 1 : 0
  name  = "\${var.cluster_name}-eks-logging-enabled"
  source { owner = "AWS"; source_identifier = "EKS_CLUSTER_LOGGING_ENABLED" }
  scope  { compliance_resource_types = ["AWS::EKS::Cluster"] }
  depends_on = [aws_config_configuration_recorder.main]
}

# Rule 2: Is the EKS API endpoint private?
resource "aws_config_config_rule" "eks_endpoint_no_public" {
  count = var.enable_config ? 1 : 0
  name  = "\${var.cluster_name}-eks-endpoint-private"
  source { owner = "AWS"; source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS" }
  scope  { compliance_resource_types = ["AWS::EKS::Cluster"] }
  depends_on = [aws_config_configuration_recorder.main]
}

# Rule 3: Are Kubernetes secrets encrypted with KMS?
resource "aws_config_config_rule" "eks_secrets_encrypted" {
  count = var.enable_config ? 1 : 0
  name  = "\${var.cluster_name}-eks-secrets-encrypted"
  source { owner = "AWS"; source_identifier = "EKS_SECRETS_ENCRYPTED" }
  scope  { compliance_resource_types = ["AWS::EKS::Cluster"] }
  depends_on = [aws_config_configuration_recorder.main]
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
config: "⚙️ AWS Config" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  rules: "Compliance Rules" {
    style.fill: "#282a36"; style.stroke: "#ffb86c"
    r1: "Is EKS Logging Enabled?" { shape: rectangle; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
    r2: "Is Endpoint Private?" { shape: rectangle; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
    r3: "Are Secrets Encrypted?" { shape: rectangle; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  }
}
eks: "⬡ EKS Cluster" { shape: package; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
c1: "✅ COMPLIANT" { shape: callout; style.fill: "#50fa7b"; style.font-color: "#282a36" }
c2: "❌ NON_COMPLIANT" { shape: callout; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
eks -> config.rules: "Evaluate" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
config.rules -> c1: "Pass" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }
config.rules -> c2: "Fail" { style.stroke: "#ff5555"; style.stroke-dash: 5 }`,
            note: "Rules flag non-compliance but do NOT auto-remediate — you decide what to fix.",
            explain: "Three AWS-managed rules check EKS security posture: <strong>Is logging enabled?</strong> (api, audit, etc.), <strong>Is the API private?</strong> (no public endpoint), and <strong>Are secrets encrypted?</strong> (KMS envelope encryption). Non-compliant resources are flagged on the Config dashboard but <strong>not automatically remediated</strong>."
          },
        ]
      },
    ];

    const BADGES = { gd: 'badge-gd', cfg: 'badge-cfg' };
    const BADGE_LABEL = { gd: 'GuardDuty', cfg: 'Config' };

    let html = '', stepNum = 0, summaryRows = '';
    STEPS.forEach(phase => {
      html += `<div class="phase"><h2>${phase.phase}</h2>`;
      phase.steps.forEach(s => {
        stepNum++;
        html += `<div class="step"><h3><span class="step-number">${stepNum}</span>${s.title} <span><span class="badge ${BADGES[s.cat]}">${BADGE_LABEL[s.cat]}</span> ${s.time}</span></h3>`;
        html += `<pre><code class="language-hcl">${escHtml(s.hcl)}</code></pre>`;
        if (s.d2) html += `<div class="d2-diagram loading" data-d2="${btoa(unescape(encodeURIComponent(s.d2)))}">Loading diagram...</div>`;
        if (s.explain) html += `<div class="explain">${s.explain}</div>`;
        if (s.note) html += `<div class="note">💡 ${s.note}</div>`;
        html += `</div>`;
        summaryRows += `<tr><td>${stepNum}</td><td>${s.title}</td><td><span class="badge ${BADGES[s.cat]}">${BADGE_LABEL[s.cat]}</span></td><td>${s.time}</td></tr>`;
      });
      html += `</div>`;
    });
    summaryRows += `<tr style="color:#ff79c6;font-weight:bold"><td></td><td><strong>Total: ~10 resources</strong></td><td></td><td><strong>~55s</strong></td></tr>`;

    document.getElementById('content').innerHTML = html;
    document.getElementById('summary-table').innerHTML = summaryRows;

    function escHtml(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
    hljs.highlightAll();

    document.querySelectorAll('.d2-diagram[data-d2]').forEach(el => {
      const src = decodeURIComponent(escape(atob(el.dataset.d2)));
      fetch('https://kroki.io/d2/svg', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: src })
        .then(r => { if (!r.ok) throw new Error(r.status); return r.text() })
        .then(svg => { el.innerHTML = svg; el.classList.remove('loading'); el.classList.add('loaded') })
        .catch(e => { el.innerHTML = `<span style="color:#ff5555">Diagram failed: ${e.message}</span>`; el.classList.remove('loading') });
    });

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry, i) => {
        if (entry.isIntersecting) { setTimeout(() => entry.target.classList.add('visible'), i * 100); observer.unobserve(entry.target); }
      });
    }, { threshold: 0.1 });
    document.querySelectorAll('.phase, .step, .summary').forEach(el => observer.observe(el));

    window.addEventListener('scroll', () => {
      const h = document.documentElement;
      document.getElementById('progressBar').style.width = (h.scrollTop / (h.scrollHeight - h.clientHeight)) * 100 + '%';
    });
  </script>
</body>

</html>
