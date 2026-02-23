<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secrets Manager Module — Build Steps</title>
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
    .phase { margin: 3rem 0; padding: 1.5rem; border-left: 4px solid #f1fa8c; background: #1e1f29; border-radius: 0 8px 8px 0; opacity: 0; transform: translateY(30px); transition: all .6s ease }
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
    .badge-enc { background: #ff5555; color: #f8f8f2 }
    .badge-sec { background: #f1fa8c; color: #282a36 }
    .badge-iam { background: #ffb86c; color: #282a36 }
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
    <h1>🔐 Secrets Manager Module</h1>
    <p class="subtitle">KMS-encrypted vault for database credentials, API keys, and application configuration</p>

    <div class="explain"
      style="margin-bottom: 3rem; background: #1e1f29; padding: 1.5rem; border-left: 4px solid #f1fa8c; border-radius: 8px;">
      <h3 style="color: #f1fa8c; margin-bottom: 0.5rem;">🔐 Module Overview</h3>
      This module creates a <strong>secure secrets vault</strong> independent from the EKS cluster, with its own dedicated KMS key for encryption:
      <ul style="margin-left: 1.5rem; margin-top: 0.5rem; color: #f8f8f2;">
        <li><strong>Dedicated KMS Key:</strong> Separate from EKS — different blast radius if compromised</li>
        <li><strong>Database Credentials:</strong> Username, password, host, port, engine (JSON object)</li>
        <li><strong>API Keys:</strong> External service API keys and secrets</li>
        <li><strong>App Configuration:</strong> Arbitrary key-value pairs stored as encrypted JSON</li>
        <li><strong>Read-Only IAM Policy:</strong> Least-privilege access for pods via IRSA</li>
      </ul>
      <div style="margin-top: 0.8rem; padding: 0.5rem 0.8rem; background: #282a36; border-radius: 4px; border-left: 3px solid #8be9fd; color: #8be9fd; font-size: 0.9rem;">
        💡 <strong>Access Methods:</strong> External Secrets Operator (syncs to K8s Secrets), CSI Secrets Store Driver (mounts as files), or AWS SDK in application code.
      </div>
      <em style="color: #6272a4; display: block; margin-top: 0.5rem;">📂 Source: <code>modules/secrets-manager/main.tf</code> · <code>variables.tf</code> · <code>outputs.tf</code></em>
    </div>

    <div id="content"></div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📥 Input Variables</h2>
      <table class="var-table">
        <thead><tr><th>Variable</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>name_prefix</code></td><td><code>string</code></td><td>—</td><td>Prefix for resource names</td></tr>
          <tr><td><code>create_db_secret</code></td><td><code>bool</code></td><td><code>false</code></td><td>Create database credentials secret</td></tr>
          <tr><td><code>db_username</code></td><td><code>string</code> 🔒</td><td><code>""</code></td><td>Database username (sensitive)</td></tr>
          <tr><td><code>db_password</code></td><td><code>string</code> 🔒</td><td><code>""</code></td><td>Database password (sensitive)</td></tr>
          <tr><td><code>db_engine</code></td><td><code>string</code></td><td><code>"postgres"</code></td><td>Database engine type</td></tr>
          <tr><td><code>db_host</code></td><td><code>string</code></td><td><code>""</code></td><td>Database hostname/endpoint</td></tr>
          <tr><td><code>db_port</code></td><td><code>number</code></td><td><code>5432</code></td><td>Database port</td></tr>
          <tr><td><code>db_name</code></td><td><code>string</code></td><td><code>""</code></td><td>Database name</td></tr>
          <tr><td><code>create_api_secret</code></td><td><code>bool</code></td><td><code>false</code></td><td>Create API keys secret</td></tr>
          <tr><td><code>api_key</code></td><td><code>string</code> 🔒</td><td><code>""</code></td><td>API key value (sensitive)</td></tr>
          <tr><td><code>api_secret</code></td><td><code>string</code> 🔒</td><td><code>""</code></td><td>API secret value (sensitive)</td></tr>
          <tr><td><code>create_app_config_secret</code></td><td><code>bool</code></td><td><code>false</code></td><td>Create application config secret</td></tr>
          <tr><td><code>app_config</code></td><td><code>map(string)</code> 🔒</td><td><code>{}</code></td><td>App config key-value pairs (sensitive)</td></tr>
          <tr><td><code>tags</code></td><td><code>map(string)</code></td><td><code>{}</code></td><td>Tags to apply to all resources</td></tr>
        </tbody>
      </table>
    </div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📤 Outputs</h2>
      <table class="var-table">
        <thead><tr><th>Output</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>kms_key_id</code> / <code>kms_key_arn</code></td><td>KMS key used for secrets encryption</td></tr>
          <tr><td><code>db_secret_arn</code> / <code>db_secret_name</code></td><td>Database credentials secret ARN and name</td></tr>
          <tr><td><code>api_secret_arn</code> / <code>api_secret_name</code></td><td>API keys secret ARN and name</td></tr>
          <tr><td><code>app_config_secret_arn</code> / <code>app_config_secret_name</code></td><td>Application config secret ARN and name</td></tr>
          <tr><td><code>read_secrets_policy_arn</code></td><td>ARN of the read-only IAM policy (attach to IRSA roles)</td></tr>
          <tr><td><code>read_secrets_policy_name</code></td><td>Name of the read-only IAM policy</td></tr>
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
        phase: "KMS Encryption Key", steps: [
          {
            title: "Create Dedicated KMS Key", cat: "enc", time: "~10s",
            hcl: `resource "aws_kms_key" "secrets" {
  # Only create if at least one secret is enabled
  count = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0

  description             = "KMS key for \${var.name_prefix} secrets encryption"
  deletion_window_in_days = 7        # 7-day grace period
  enable_key_rotation     = true     # Auto-rotate annually

  tags = merge(var.tags, { Name = "\${var.name_prefix}-secrets-kms" })
}

resource "aws_kms_alias" "secrets" {
  count         = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0
  name          = "alias/\${var.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets[0].key_id
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
eks_kms: "🔑 EKS KMS Key\\n(Cluster Secrets)" { shape: hexagon; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
sm_kms: "🔑 Secrets Manager KMS Key\\n(App Credentials)" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
blast: "💥 Blast Radius" {
  style.fill: "#1e1f29"; style.stroke: "#f1fa8c"
  b1: "If EKS key compromised:\\nOnly K8s secrets exposed" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  b2: "If SM key compromised:\\nOnly app creds exposed" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
eks_kms -> blast.b1 { style.stroke: "#6272a4"; style.stroke-dash: 5 }
sm_kms -> blast.b2 { style.stroke: "#ff5555"; style.stroke-dash: 5 }`,
            note: "Separate KMS key from EKS — different blast radius if compromised.",
            explain: "A <strong>dedicated KMS key</strong> for Secrets Manager means it has separate access policies from the EKS key. If one key is compromised, the other remains safe. The <code>||</code> (OR) operator in the count ensures the key is created only if at least one secret is enabled. <code>deletion_window_in_days = 7</code> prevents accidental permanent deletion."
          },
        ]
      },
      {
        phase: "Secrets (Conditional Creation)", steps: [
          {
            title: "Create Database Credentials Secret", cat: "sec", time: "~10s",
            hcl: `resource "aws_secretsmanager_secret" "db_credentials" {
  count                   = var.create_db_secret ? 1 : 0
  name_prefix             = "\${var.name_prefix}-db-credentials-"
  kms_key_id              = aws_kms_key.secrets[0].id
  recovery_window_in_days = 7     # Recoverable for 7 days after deletion

  tags = merge(var.tags, { Name = "\${var.name_prefix}-db-credentials", Type = "database" })
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  count     = var.create_db_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.db_credentials[0].id
  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    engine   = var.db_engine        # "postgres", "mysql", etc.
    host     = var.db_host
    port     = var.db_port
    dbname   = var.db_name
  })
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
sm: "🔐 Secrets Manager" {
  style.fill: "#1e1f29"; style.stroke: "#f1fa8c"; style.stroke-width: 2
  db: "🗄️ Database Credentials" {
    shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36"
  }
}
json: "JSON Structure" {
  style.fill: "#282a36"; style.stroke: "#6272a4"
  k1: "username: admin" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  k2: "password: ********" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  k3: "engine: postgres" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  k4: "host: rds.amazonaws.com" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
kms: "🔑 KMS Key" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
json -> sm.db: "jsonencode()" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
kms -> sm.db: "Encrypts at rest" { style.stroke: "#ff5555"; style.stroke-dash: 5 }`,
            note: "recovery_window_in_days = 7 prevents accidental permanent deletion.",
            explain: "Database credentials are stored as a <strong>JSON object</strong> using <code>jsonencode()</code>. The secret has two parts: the <strong>secret resource</strong> (metadata, KMS key, tags) and the <strong>secret version</strong> (actual value). Sensitive variables (<code>db_username</code>, <code>db_password</code>) are marked <code>sensitive = true</code> to prevent display in terraform plan output."
          },
          {
            title: "Create API Keys + App Config Secrets", cat: "sec", time: "~10s",
            hcl: `# --- API Keys Secret ---
resource "aws_secretsmanager_secret" "api_keys" {
  count                   = var.create_api_secret ? 1 : 0
  name_prefix             = "\${var.name_prefix}-api-keys-"
  kms_key_id              = aws_kms_key.secrets[0].id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  count     = var.create_api_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.api_keys[0].id
  secret_string = jsonencode({
    api_key    = var.api_key
    api_secret = var.api_secret
  })
}

# --- Application Config Secret ---
resource "aws_secretsmanager_secret" "app_config" {
  count                   = var.create_app_config_secret ? 1 : 0
  name_prefix             = "\${var.name_prefix}-app-config-"
  kms_key_id              = aws_kms_key.secrets[0].id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "app_config" {
  count         = var.create_app_config_secret ? 1 : 0
  secret_id     = aws_secretsmanager_secret.app_config[0].id
  secret_string = jsonencode(var.app_config)    # Entire map → JSON string
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
sm: "🔐 AWS Secrets Manager" {
  style.fill: "#1e1f29"; style.stroke: "#f1fa8c"; style.stroke-width: 2
  db: "🗄️ Database Credentials" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  api: "🔌 External API Keys" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  app: "⚙️ App Configurations" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
}
kms: "🔑 Dedicated KMS Key" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
kms -> sm.db: "Encrypts" { style.stroke: "#ff79c6"; style.stroke-dash: 5 }
kms -> sm.api: "Encrypts" { style.stroke: "#ff79c6"; style.stroke-dash: 5 }
kms -> sm.app: "Encrypts" { style.stroke: "#ff79c6"; style.stroke-dash: 5 }`,
            note: "All secrets are conditionally created using count flags — only pay for what you use.",
            explain: "API keys and app config follow the same pattern as DB credentials: <strong>conditionally created</strong> using <code>count</code> flags. App config uses <code>jsonencode(var.app_config)</code> to convert an arbitrary Terraform map into a JSON string. All three secret types share the same dedicated KMS key for encryption at rest."
          },
        ]
      },
      {
        phase: "IAM Access Policy (Least Privilege)", steps: [
          {
            title: "Create Read-Only IAM Policy", cat: "iam", time: "~5s",
            hcl: `resource "aws_iam_policy" "read_secrets" {
  count       = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0
  name_prefix = "\${var.name_prefix}-read-secrets-"
  description = "Allow reading secrets from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = concat(
          var.create_db_secret  ? [aws_secretsmanager_secret.db_credentials[0].arn] : [],
          var.create_api_secret ? [aws_secretsmanager_secret.api_keys[0].arn] : [],
          var.create_app_config_secret ? [aws_secretsmanager_secret.app_config[0].arn] : []
        )
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = [aws_kms_key.secrets[0].arn]     # Only our dedicated KMS key
      }
    ]
  })
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
pod: "📦 Application Pod\\n(via IRSA)" { shape: package; style.fill: "#8be9fd"; style.font-color: "#282a36" }
iam: "🛡️ IAM Policy (Read-Only)" {
  style.fill: "#1e1f29"; style.stroke: "#ff5555"; style.stroke-width: 2
  p1: "ALLOW: secretsmanager:GetSecretValue\\n(Only specific ARNs — no wildcards)" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "ALLOW: kms:Decrypt\\n(Only dedicated KMS Key)" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
sm: "🔐 Secrets Vault" { shape: cylinder; style.fill: "#bd93f9"; style.font-color: "#282a36" }
pod -> iam: "AssumeRole via IRSA" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
iam.p1 -> sm: "Read Secret" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }
iam.p2 -> sm: "Decrypt via KMS" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }`,
            note: "Only specific secret ARNs (no wildcards). kms:Decrypt required to read encrypted values.",
            explain: "The IAM policy uses <code>concat()</code> to dynamically build the list of allowed secret ARNs based on which secrets were actually created. <strong>No wildcards</strong> — pods can only read their specific secrets. <code>kms:Decrypt</code> is required because the secrets are encrypted with the dedicated KMS key. Attach this policy to an IRSA role for pod-level access."
          },
        ]
      },
    ];

    const BADGES = { enc: 'badge-enc', sec: 'badge-sec', iam: 'badge-iam' };
    const BADGE_LABEL = { enc: 'Encryption', sec: 'Secrets', iam: 'IAM' };

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
    summaryRows += `<tr style="color:#ff79c6;font-weight:bold"><td></td><td><strong>Total: ~10 resources</strong></td><td></td><td><strong>~35s</strong></td></tr>`;

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
