# Argo Operator & User Manual

**Argo** is a self-hosted multi-bot automation workspace that runs on a single Linux container host behind Google SSO (`oauth2-proxy`). Administrators deploy three containers from one Compose file; workspace users create and refine bots in plain English, receive live-streamed replies with inline tool progress chips and non-blocking queued follow-ups, group specialists into shared Rooms with fast auto-routing, inspect live dashboards side-by-side in Split View, review external actions before sending, and automate isolated XFCE Virtual Desktops without writing code or rebuilding containers.

---

## Table of Contents

- [Chapter 1: Installation and Administration](#chapter-1-installation-and-administration)
  - [1.1 System Requirements and Architecture](#11-system-requirements-and-architecture)
  - [1.2 Generate Encryption and Session Secrets](#12-generate-encryption-and-session-secrets)
  - [1.3 Configure Google Cloud OAuth](#13-configure-google-cloud-oauth)
  - [1.4 Configure Compose and Start Argo](#14-configure-compose-and-start-argo)
  - [1.5 Reverse Proxy Configuration](#15-reverse-proxy-configuration)
  - [1.6 First Sign-In Checklist](#16-first-sign-in-checklist)
  - [1.7 Operations, Backups, Upgrades, and Local Tests](#17-operations-backups-upgrades-and-local-tests)
- [Chapter 2: Users Usage Guide](#chapter-2-users-usage-guide)
  - [2.1 Workspace Tour](#21-workspace-tour)
  - [2.2 Creating Bots, Team Rooms, and Starter Crews](#22-creating-bots-team-rooms-and-starter-crews)
  - [2.3 Chatting, Live Streaming, Follow-Up Queue, Mentions, Files, and Self-Tuning](#23-chatting-live-streaming-follow-up-queue-mentions-files-and-self-tuning)
  - [2.4 Skills and Named Routines](#24-skills-and-named-routines)
  - [2.5 Multi-Bot Rooms, Auto-Picker Routing, and Delegation Plans](#25-multi-bot-rooms-auto-picker-routing-and-delegation-plans)
  - [2.6 Reviewing Actions in Approvals and Writing Rules](#26-reviewing-actions-in-approvals-and-writing-rules)
  - [2.7 Interactive Pages and Side-by-Side Split View](#27-interactive-pages-and-side-by-side-split-view)
  - [2.8 Connected Apps and the Secrets Vault](#28-connected-apps-and-the-secrets-vault)
  - [2.9 Virtual Desktops, Teach-a-Task Recording, and Live Takeover](#29-virtual-desktops-teach-a-task-recording-and-live-takeover)
  - [2.10 Real-Life Usage Playbooks](#210-real-life-usage-playbooks)
  - [2.11 Monitoring Activity, Token Budgets, and Diagnostics](#211-monitoring-activity-token-budgets-and-diagnostics)
- [Reference Documentation](#reference-documentation)

---

## Chapter 1: Installation and Administration

This chapter covers host preparation, secret generation, Google OAuth setup, `compose.yml` deployment, HTTPS reverse proxying, and ongoing maintenance.

### 1.1 System Requirements and Architecture

- **Host OS:** Linux x86_64 or arm64 with Docker Engine (`docker compose`) or Podman (`podman compose`).
- **Resources:** `4+` vCPUs and `8+ GB` RAM for Cloud API workloads; `16+ GB` RAM recommended if running multiple concurrent Virtual Desktops (`2 GB` RAM ceiling each).
- **Network & TLS:** Public DNS record (for example, `argo.example.com`) and a host HTTPS reverse proxy (Caddy, Nginx, or Traefik) forwarding to `127.0.0.1:4180`.

All services run on a single isolated Docker bridge network (`argo-net`) defined in [`compose.yml`](compose.yml):

| Service / Container | Image & Runtime | Resource Limit | Role |
| :--- | :--- | :--- | :--- |
| `oauth2-proxy` | `quay.io/oauth2-proxy/oauth2-proxy:v7.15.6` | `256m` RAM · `0.5` CPU | Binds `127.0.0.1:4180`, enforces Google SSO, forwards authenticated identity (`X-Auth-Request-*`), and passes `/hooks/*` unauthenticated for signed webhooks and Telegram updates. |
| `argo-core` | `ghcr.io/dimitribellini/argo:latest` (`Fedora 45` · `Python 3.15` · static React 19 SPA) | `2g` RAM · `2.0` CPU | Serves the Web UI and `/api/*` internally on `:8000`, runs scheduled bot routines, stores state in SQLite WAL + FTS5 (`/data/argo.db`), and isolates per-user uploaded files in `/data/workspace_files/<user_ns>/`. |
| `valkey` | `valkey/valkey:9.1-alpine` | `256m` RAM · `0.5` CPU | Internal event bus, stream consumer groups, and distributed locks on `:6379` (never exposed outside `argo-net`). |
| `argo-desktop-<bot_slug>` | `lscr.io/linuxserver/webtop:fedora-xfce` | `2g` RAM · `1.5` CPU | Spawned on demand per Virtual Desktop bot; streams HTML5 `Selkies` (`:3000`) and exposes Chromium CDP (`:9222`) + Desktop MCP (`:9223/mcp`) over `argo-net`, persisting profile data in `/srv/argo/desktops/<bot_slug>`. |

### 1.2 Generate Encryption and Session Secrets

Generate two distinct cryptographic keys on the host before editing `compose.yml`:

```bash
# 1. ARGO_MASTER_KEY (Fernet key encrypting stored OAuth tokens, LLM keys, and Vault secrets)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 2. OAUTH2_PROXY_COOKIE_SECRET (32-byte URL-safe base64 session cookie key)
python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Keep a secure offline copy of `ARGO_MASTER_KEY`. Existing encrypted credentials in SQLite cannot be decrypted if this key is lost.

### 1.3 Configure Google Cloud OAuth

#### A. Web UI Sign-In (`oauth2-proxy` — Required)

1. Open Google Cloud Console → **Google Auth Platform** (or **APIs & Services → Credentials**).
2. Under **Audience**, select **Internal** (Google Workspace organizations) or **External**.
3. Create an **OAuth Client ID** of type **Web application**.
4. Add your authorized redirect URI:
   - `https://argo.example.com/oauth2/callback`
5. Record the **Client ID** and **Client Secret** for `OAUTH2_PROXY_CLIENT_ID` and `OAUTH2_PROXY_CLIENT_SECRET`.

#### B. Optional Multi-Account Gmail Connectors (`Personal Gmail` and `Business Gmail`)

Google Cloud enforces **Audience (`Internal` vs `External`)** at the project level rather than per OAuth client. Authorizing a `@gmail.com` address against an `Internal` Workspace client fails with `Error 403: org_internal`. If users will connect both company Workspace mail and personal `@gmail.com` inboxes to bots, configure two Google Cloud projects:

| Google Cloud Project | Audience | Authorized Redirect URIs | Where Configured |
| :--- | :--- | :--- | :--- |
| **Project 1** *(Workspace)* | **Internal** | `https://argo.example.com/oauth2/callback`<br>`https://argo.example.com/api/integrations/google/callback` | SSO variables in `compose.yml`, plus optional `ARGO_GOOGLE_CLIENT_ID` / `ARGO_GOOGLE_CLIENT_SECRET` for 1-click Business Gmail onboarding. |
| **Project 2** *(Personal)* | **External** (`Testing` or `In Production`) | `https://argo.example.com/api/integrations/google/callback` | Entered once in the Web UI under **Settings → Integrations → + Connect Google Account → Personal Gmail**. |

Enable the **Gmail API** (and **Google Calendar API** if needed) in each project used for bot mailbox connectors. If Project 2 remains in `Testing`, add authorized `@gmail.com` addresses under **Test users** (refresh tokens in `Testing` expire every 7 days and require **Re-authorize**; publishing **In Production** avoids the 7-day expiry). Set `OAUTH2_PROXY_EMAIL_DOMAINS: "your-org.com"` in `compose.yml` to restrict Web UI logins to company employees while still allowing external personal `@gmail.com` mailboxes inside **Integrations**.

### 1.4 Configure Compose and Start Argo

Create the host directory for persistent Virtual Desktop profiles:

```bash
sudo mkdir -p /srv/argo/desktops
sudo chmod 0755 /srv/argo/desktops
```

Edit [`compose.yml`](compose.yml) and set the environment variables:

| Variable | Service | Required | Description |
| :--- | :--- | :--- | :--- |
| `ARGO_MASTER_KEY` | `argo-core` | Yes | Fernet base64 key generated in Step 1.2. |
| `ARGO_PUBLIC_BASE_URL` | `argo-core` | Yes | External HTTPS URL (`https://argo.example.com`), used for OAuth callbacks and Telegram webhooks. |
| `ARGO_DB_PATH` | `argo-core` | No | SQLite database path inside container (default: `/data/argo.db`). |
| `ARGO_WORKSPACE_FILES_ROOT` | `argo-core` | No | Uploaded file directory (default: `<db_dir>/workspace_files`, which resolves to `/data/workspace_files`). |
| `ARGO_DESKTOP_VOLUMES_ROOT` | `argo-core` | No | Host bind mount root for Virtual Desktop state (default: `/srv/argo/desktops`). |
| `ARGO_DESKTOP_IDLE_TIMEOUT_SECONDS` | `argo-core` | No | Idle timeout in seconds before auto-hibernating running Virtual Desktops (default: `300`). |
| `ARGO_VALKEY_URL` | `argo-core` | No | Internal Valkey connection URL (default: `valkey://valkey:6379/0`). |
| `ARGO_DOCKER_NETWORK` | `argo-core` | No | Shared container network name (default: `argo-net`). |
| `ARGO_GOOGLE_CLIENT_ID` | `argo-core` | No | Optional shared Business Google OAuth Client ID for 1-click onboarding in the Web UI. |
| `ARGO_GOOGLE_CLIENT_SECRET` | `argo-core` | No | Companion Client Secret for `ARGO_GOOGLE_CLIENT_ID`. |
| `OAUTH2_PROXY_CLIENT_ID` | `oauth2-proxy` | Yes | Google OAuth Client ID for Web UI sign-in. |
| `OAUTH2_PROXY_CLIENT_SECRET` | `oauth2-proxy` | Yes | Google OAuth Client Secret for Web UI sign-in. |
| `OAUTH2_PROXY_COOKIE_SECRET` | `oauth2-proxy` | Yes | 32-byte URL-safe base64 secret generated in Step 1.2. |
| `OAUTH2_PROXY_REDIRECT_URL` | `oauth2-proxy` | Yes | `https://argo.example.com/oauth2/callback`. |
| `OAUTH2_PROXY_EMAIL_DOMAINS` | `oauth2-proxy` | Yes | `"*"` for any Google account, or `"your-org.com"` to restrict logins to one Workspace domain. |

> **Credential hygiene:** LLM API keys, Telegram BotFather tokens, LinkedIn tokens, and SSH/portal credentials are entered inside the Web UI and encrypted in SQLite. Do not place user credentials in `compose.yml`.

Start the stack:

```bash
docker compose pull && docker compose up -d
# Or with Podman:
podman compose pull && podman compose up -d
```

To build the `argo-core` image directly from source using [`Dockerfile`](Dockerfile):

```bash
docker build -t ghcr.io/dimitribellini/argo:latest .
docker compose up -d
```

### 1.5 Reverse Proxy Configuration

Forward HTTPS traffic to `127.0.0.1:4180`. Disable proxy buffering so Server-Sent Events on `/api/activity/stream` deliver live token streaming (`turn_stream`), inline tool progress chips, and real-time workspace updates without delay; forward WebSocket upgrade headers for `Selkies` Virtual Desktop streams (`/api/desktops/*/selkies/ws`); and permit uploads at least `12 MB` (Argo enforces a `10 MB` cap on `/api/files`).

**Caddy example:**

```caddyfile
argo.example.com {
    reverse_proxy 127.0.0.1:4180
}
```

**Nginx example:**

```nginx
server {
    listen 443 ssl http2;
    server_name argo.example.com;

    # Increase above Argo's 10 MB per-file upload limit
    client_max_body_size 12m;

    location / {
        proxy_pass http://127.0.0.1:4180;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for Selkies Virtual Desktops
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Disable buffering for SSE event streams and streaming uploads
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
    }
}
```

### 1.6 First Sign-In Checklist

After opening `https://argo.example.com` and signing in via Google SSO:

1. **Add AI Model Providers (`Settings → Models & Usage`):**
   - Click **`+ Add AI Model`** and enter an API key (or local `Ollama` endpoint) for one or more providers (`Google Gemini`, `Anthropic`, `OpenAI`, `xAI`, `OpenRouter`, or `Ollama`).
   - Recommended pairing: set **Gemini 3.8 Flash** as the default for high-volume scheduled checks and assign **Gemini 4 Argon** on coordinator or writer bots. Click **Test** to verify latency and credentials.
2. **Connect Shared Apps (`Settings → Integrations`):**
   - Click **`+ Connect Google Account`**, **`+ Connect Telegram Bot`**, **`+ Connect LinkedIn`**, or **`+ Add Webhook`** as needed. Click **Verify** (and **Send Test** for Telegram) to confirm connectivity.
3. **Add Encrypted Vault Credentials (`Settings → Secrets Vault`):**
   - Store any shared SSH keys/passwords, portal logins, or bearer tokens under **New Secret** and restrict access under **Bot Access → Selected Bots**.
4. **Optional Baseline Memory (`Settings → Writing & Memory`):**
   - Paste existing tone rules or safety constraints into **Import Notes & Preferences (Bring Your Memory)** and click **Import Memory Rules**.

### 1.7 Operations, Backups, Upgrades, and Local Tests

- **Health Check:** Confirm container health with `docker compose ps` (`argo-core` checks `http://127.0.0.1:8000/api/health` every `30s`) and inspect runtime status in **Settings → Diagnostics** (shows Valkey status, SQLite WAL status, scrubbed server logs, and run traces).
- **Upgrades:** Pull new container images and recreate containers without losing state:
  ```bash
  docker compose pull && docker compose up -d
  ```
- **Backups:** Back up three items together:
  1. The `argo-data` volume (`/data/argo.db` SQLite database and `/data/workspace_files/`). Quiesce writes or use SQLite online backup (`sqlite3 /data/argo.db ".backup '/backup/argo.db'"`).
  2. `/srv/argo/desktops/` (persistent browser logins and local tools for desktop bots).
  3. `ARGO_MASTER_KEY` from `compose.yml` (stored securely separate from the database).
- **Local Developer Verification:**
  ```bash
  cd frontend && npm run build
  cd .. && PYTHONPATH=backend pytest -q
  # Standard library fallback:
  PYTHONPATH=backend python3 -m unittest discover -s tests -v
  ```

---

## Chapter 2: Users Usage Guide

This chapter explains daily workflows using Argo's Web UI controls. All bot creation, scheduling, file sharing, page building, and virtual desktop recording happen directly inside the browser without touching server configs.

### 2.1 Workspace Tour

Argo opens in a focused two-pane workspace (sidebar + active canvas) and expands automatically into a three-pane **Split View** when a Page is docked beside a conversation. Toggle **Light** / **Dark** theme anytime from the icon beside **Settings** at the bottom-left.

| Area | Where to Find It | What It Does |
| :--- | :--- | :--- |
| **`+ New Bot` & Search** | Top-left sidebar | Opens the 4-tab creator (**Quick Setup (Chat)**, **Detailed Builder**, **Team Room**, **Team Packs**). Search filters bots, Rooms, and Pages by name. |
| **Pinned Hero Tiles** | Upper sidebar | Two-column quick-access cards for starred bots (hover any bot row and click **Pin**). |
| **`Rooms` & `Bots`** | Sidebar list | Shared `2–6` bot group chats (**Rooms**, shown once created) and individual bots organized by collapsible **Sidebar Group** folders. A solid `#3b72b2` dot indicates unread updates; opening a thread loads the latest `40` messages (**Load earlier messages** fetches history). Hover any bot row (or open its **Details** footer / **Settings → Desktops**) for 2-step **Delete Bot → Confirm Delete** cleanup, which purges history, supersedes pending approvals, and removes any dedicated Virtual Desktop container. |
| **`Approvals`** | Middle sidebar | Queue of outgoing emails, social/Telegram messages, and proposed bot privilege upgrades (**Waiting for Review** and **History**). |
| **`Activity`** | Middle sidebar | Live chronological workspace timeline with **Hide quiet checks**, **Timeline / Workflows** view, filters, and a quick **`@Bot`** instruction bar. |
| **`Pages` (`+ New`)** | Middle sidebar | Interactive dashboards built by bots or templates. Hover any Page and click the columns icon to dock it beside your current chat (**Split View**). |
| **`Settings`** | Bottom-left anchor | Six tabs: **Integrations**, **Secrets Vault**, **Models & Usage**, **Desktops**, **Writing & Memory**, and **Diagnostics**. |
| **Top Header Bar** | Top of active thread | Shows pending approvals pill (shortcut to **Approvals**), bot-owned Page pills, **Hub Board** (`Split View` toggle), **Open Desktop** (for desktop bots), **Run Now**, and **Details**. |
| **`Details` Panel** | Right side (`Details` button) | Slide-over or docked panel with three tabs for bots (**Details \| Library \| Computer**) or Room configuration (**Details**). |

### 2.2 Creating Bots, Team Rooms, and Starter Crews

Click **`+ New Bot`** at the top-left and choose one of four workflows:

| Tab | Best For | How It Works |
| :--- | :--- | :--- |
| **`Quick Setup (Chat)`** | Fast conversational setup | Choose a **Bot Name**, badge **Color**, **Shape**, optional **What should it help with?**, and optional **Sidebar Group**, then click **Start Onboarding Chat**. The bot sends the first message in chat, asks targeted questions with clickable quick-reply chips, and configures its own instructions and rules from your answers. |
| **`Detailed Builder`** | Full upfront control | Pick a starter (**Email / Web Scout**, **Story & Copy Writer**, **Approval Notifier**, **Supervisor Bot**, or **2-Bot Pipeline**) or describe the job in plain English. Click **Preview Understanding** to verify Argo's interpreted job, schedule, autonomy, and rules; select **Connected Apps**, **Execution Environment** (**Cloud API** vs **Virtual Desktop**), and **When sending** policy; then click **Create Bot**. |
| **`Team Room`** | `2–6` bots collaborating visibly | Enter **Room Title**, optional **Sidebar Group**, select `2–6` member bots, choose **Speaker Routing** (**Auto-Pick Best Bot**, **Lead / Coordinator First**, or **Fixed Stage Order**) and a **Lead Coordinator** fallback, optionally check **Ask me before one bot triggers another in this Room**, and click **Create Room**. |
| **`Team Packs`** | 1-click multi-bot teams or JSON import | Click **Install Crew** on a built-in pack (**Operations Coordinator Crew**, **Website & Release QA Crew**, or **Inbox & Briefing Crew**) to create bots, a shared Room, and a Board together, or paste an exported Team Pack / Bot Blueprint `.json` (credentials are never exported). |

### 2.3 Chatting, Live Streaming, Follow-Up Queue, Mentions, Files, and Self-Tuning

Every `1:1` bot chat and Team Room shares the same clean bottom composer (`[+] [@] Message... [↑]`):

- **Live Streaming Replies & Inline Tool Progress Chips:**
  - Replies stream word-by-word directly in the conversation as the model writes, holding back internal JSON action framing so only clean prose is shown.
  - When a bot fetches RSS feeds, web pages, Gmail threads, public Telegram channels, or Virtual Desktop steps, compact inline chips appear live in the reply header (**Running** → **Done · Xs** or **Note**) so you can see progress in real time. Completed tool chips remain visible on the finished message.
- **Non-Blocking Follow-Up Queue (`N queued`):**
  - Sending a message returns immediately without locking the composer. While a bot or Team Room is still replying, you can keep typing and send additional follow-up instructions right away; Argo queues them sequentially per thread and shows an **`N queued`** indicator until each turn starts.
- **Stop Current Reply (`■ Stop`):**
  - Click **Stop** on the streaming header (or the **`■`** button next to Send in the composer) to halt inference or an in-flight tool call immediately. Argo keeps any partial reply text and completed tool chips with a **`Stopped`** badge, releases execution locks right away, and lets you send your next message immediately.
- **Attach Private Files (`+` button or Drag-and-Drop, max `10 MB` per file) & 1-Click Downloads:**
  - Click **`+`** or drag files directly onto the composer to attach CSVs, PDFs, logs, Markdown notes, or screenshots (`<= 10 MB` per file).
  - **Per-User Privacy & Quick Download:** Files you upload (and files generated by bots via `write_workspace_file`) are stored in an isolated workspace directory tied to your signed-in account and appear as attachment pills directly on replies. Other users in the same Argo instance cannot list, view, or mention your uploaded files. Click any attachment pill or file row to preview inline, click its **Download** icon (`?download=true`) to save immediately to disk, or manage uploads anytime under **`Details → Library → My Workspace Files`** (and inside a Room's **`Details`** drawer).
- **Mention Menu (`@` button or typing `@`):**
  - Type `@` anywhere in the composer (or click **`@`**) to browse items grouped into **Bots**, **Connected Apps**, **Secrets**, **Skills**, **Pages**, and **Files**. Navigate with `ArrowUp` / `ArrowDown` and press `Enter` or `Tab`.
  - Mentions appear cleanly with their **Icon + Name** rather than raw system handles.
- **Hover Message Actions:**
  - Hover over any bot reply to reveal four compact icons:
    - **Add reaction** (`☺`): react with `👍`, `✅`, `👀`, or `🔥`.
    - **Reply** (`↩`): quote that specific message above the composer so your follow-up targets that context (and in Rooms, routes directly to that bot).
    - **Copy**: copy the reply text to your clipboard.
    - **More actions** (`⋯`): choose **Save as Skill** (save the proven workflow as a reusable playbook) or **Automate as Routine** (schedule it with presets).
- **Talk Bots into Shape (Self-Tuning vs Privilege Safety):**
  - You can update a bot's **job instructions**, **rules/never-do boundaries**, **sidebar group**, or **handoff partner** simply by telling it in `1:1` chat (for example: *"Keep bullet points to one line, always include source URLs, and ignore sponsored posts"*).
  - Requests that expand privileges — switching **When Sending** to **Auto-Send**, attaching a **Virtual Desktop**, or granting access to external **Connected Apps** — never self-activate silently. Instead, Argo creates a confirmation card in **Approvals** where you click **Approve & Apply**.

### 2.4 Skills and Named Routines

Argo encourages proving a task once in chat before scheduling it (**"Test First, Automate Second"**):

1. **Test interactively first:** Ask the bot to run your task manually in chat until the format and sources look right.
2. **Propose or save a Skill + Routine:** When a bot completes a multi-step check, it may attach a **`Save as Skill & Named Routine?`** card in chat. Adjust the **Routine name**, **Schedule**, and **Timezone**, then click **Save Skill & Activate Routine** (or hover any reply and choose **`⋯ → Save as Skill`** / **`Automate as Routine`**).
3. **Run Multiple Independent Routines per Bot (`Details → Routines`):**
   - A single bot can run multiple separate routines (for example, a fast weekday poll plus a Friday rollup).
   - Click **`+ Add Routine`** (or ask in plain English: *"Keep the weekday check and add a Monday Digest every Monday at 09:00 America/New_York"*).
   - Click any existing routine's **title** in **`Details → Routines`** to edit its **Routine name**, **Timezone**, dedicated **Task prompt**, and **No-new-items policy**:
     - **Skip quietly if no new items** *(default)*: Uses `0` AI tokens and stays silent when feeds, pages, or inboxes contain nothing new (`HTTP 304` or matching content hash).
     - **Notify if no new items**: Posts a brief `0`-token notice (`0 new items`) without invoking the AI model.
     - **Always summarize**: Runs AI synthesis on schedule even when nothing changed.
   - Use **`▶`** next to any routine to **Test routine now**, or toggle its switch on/off without deleting it.

### 2.5 Multi-Bot Rooms, Auto-Picker Routing, and Delegation Plans

A **Team Room** puts `2–6` specialist bots into a single visible conversation instead of passing tasks invisibly behind the scenes:

- **Turn Routing Priority:** Choose **Speaker Routing** (`Auto-Pick Best Bot`, `Lead / Coordinator First`, or `Fixed Stage Order`) when creating a Room or anytime inside the Room's **Details** panel:
  1. Any `@Bot` you mention speaks first (`0` extra routing tokens).
  2. Otherwise, if you used **`↩` Reply** on a bot's message, that bot responds directly.
  3. Otherwise, under **Auto-Pick Best Bot** *(default)*:
     - **Unique Capability Check (`0` tokens):** If one specialist exclusively matches the request (such as the sole **Virtual Desktop** bot for screenshots/SSL/terminal checks, or a sole connected Gmail/Telegram/LinkedIn specialist), Argo routes straight to that specialist.
     - **Fast Flash Classifier (`<= 800 ms`):** Otherwise a low-latency micro-classifier picks the best Room member from brief member descriptions and the last few messages, annotating the reply with a subtle **`Auto-picked <Bot> · <reason>`** pill. If the classifier times out or no model is configured, Argo falls back safely to the **Lead Coordinator**.
  4. Under **Lead / Coordinator First**, untagged messages go to the **Lead Coordinator**; under **Fixed Stage Order**, they start with the first bot in `stage_order`.
- **Visible Handoffs & Optional Handoff Approval:** During multi-bot handoffs in a Room, each completed speaker's message appears immediately in the thread while the next specialist streams below it, up to the Room's hop limit — or, if **Ask me before one bot triggers another in this Room** is enabled in the Room's **Details**, pauses and shows a **`Let <Bot> reply`** chip so you control every handoff.
- **Stage-by-Stage Delegation Plans:** Coordinator bots can propose a **Delegation Plan** card showing numbered stages and assigned specialists (`Stage 1`, `Stage 2`, ...). Click **`Approve & Run Plan`** to execute independent stages in parallel, pass results to downstream stages, and receive one consolidated reply from the Coordinator.

### 2.6 Reviewing Actions in Approvals and Writing Rules

Control how much autonomy each bot has under **`Details → When Sending`**:

| Mode | Behavior |
| :--- | :--- |
| **Ask First** *(default)* | Bots prepare real Gmail drafts, Telegram posts, LinkedIn posts, or configuration changes and pause them in **Approvals** until reviewed. |
| **Read Only** | Bots read permitted sources and save items into internal **Data Lists**, blocking all outbound sending tools. |
| **Auto-Send** | Bots dispatch directly within the **Daily Send Limit** (`1–50/day`). Exceeding the daily cap, targeting an unlisted destination, or tripping secret/PII checks automatically sends the item to **Approvals** instead. |

Inside **`Approvals`** (top-right badge or sidebar):
- Switch between **Waiting for Review** and **History** (`All`, `Sent`, `Rejected`).
- Click **Approve & Send** (or **Approve & Apply** for workspace upgrades), **Reject**, or **Edit**.
- When you click **Edit**, adjust the draft text, optionally enter a **Preference Saved for Future Runs** rule (or leave blank to auto-learn from the highlighted word changes), and click **Save Rule & Approve** so future drafts follow your style automatically.
- If a Telegram operator bot is connected, approval cards arrive in Telegram with **Approve / Reject** buttons (synchronized atomically with the Web UI so the same item cannot send twice). Replying directly to a Telegram approval card revises the draft and saves a rule.

### 2.7 Interactive Pages and Side-by-Side Split View

Turn any bot's collected items or workspace state into live dashboards (**`Pages`**):

1. Click **`Pages → + New`** (or ask a bot in chat) and pick a layout:
   - **Bot Hub Board**: Live directory of all bots, Rooms, schedules, and approvals with quick **Open** and trigger buttons.
   - **Live Operations Map**: Visual status map of active bots and pending reviews.
   - **Data Explorer & Charts**: Filterable charts and tables over a bot's saved **Data Lists**.
   - **Concept Playground**: Interactive visual explainers, calculators, and controls.
2. **Dock Side-by-Side (`Split View`):**
   - Click **Hub Board** in a chat header, click the **Dock beside chat** icon on any Page row or under **`Details → Library → Interactive Pages`**, or type `"can you open the html board"` directly in chat.
   - Your conversation stays open on the left while the Page runs live on the right. Clicking **`Details`** opens the inspector as a slide-over drawer so you do not lose the docked board.
3. **Update In-Place & Direct File Exports (`allow-downloads`):** Use the prompt bar at the bottom of a Page (or `@` mention the owner bot) to refine visuals or filters without changing the Page's URL (`/?view=page&slug=...`) or breaking bookmarked links. Living Pages run inside an isolated sandbox with `allow-downloads` enabled (without sharing session origin or cookies), so interactive export buttons inside a Page (such as `.csv`, `.json`, `.png`, `.svg`, `.md`, `.pdf`, or rendered `.webm` clips) download directly in Split View and standalone view, alongside the Page's **HTML** export button.

### 2.8 Connected Apps and the Secrets Vault

#### Connecting Apps (`Settings → Integrations`)
- **Gmail (`Personal Gmail` / `Business Gmail`):** Authorize multiple mailboxes under distinct names and permissions (**Read**, **Compose/Draft**, **Calendar**).
- **Telegram Operator Channel & Public Channels:**
  - Connect a BotFather bot (`+ Connect Telegram Bot`) to receive mobile approval cards, reply to revise drafts, and ask quick commands (`/status`, `/bots`, `/runs`, `/jobs`, `/approvals`, `/help`) or natural questions from Telegram.
  - Monitor public Telegram channels without admin rights using **`Watch a public channel...`** (`@channel` or `https://t.me/s/<channel>`).
- **LinkedIn & Inbound Webhooks:** Connect LinkedIn (**`+ Connect LinkedIn`**) or create HMAC-verified webhook endpoints (**`+ Add Webhook`**) to trigger bots from external systems.

Assign apps per bot in **`Details → Connected Apps → + Add`**. Bots cannot access any integration unless explicitly added to their list.

#### Managing Encrypted Credentials (`Settings → Secrets Vault`)
Store credentials (`SSH Server`, `Web Login`, `API Token`, or `Custom Secret`) without letting AI models see the secret text (**Zero-AI Exposure**):
1. Click **New Secret** in **Settings → Secrets Vault**.
2. Enter a human-friendly **Name**, pick **Credential Type**, fill endpoint and credentials, and choose **Bot Access** (`Selected Bots` by default, or `All Bots`).
3. Click **Save Secret**. Assign or unassign a secret on any bot anytime under **`Details → Vault Secrets → + Add`** (or click **Edit** on a row in **Secrets Vault** — leave password/key/token inputs blank when editing to preserve existing encrypted values while updating host fields or bot permissions).

When a bot runs a check mentioning a Vault secret, the AI model only sees the secret's name and host metadata; Argo decrypts credentials solely inside the isolated execution layer and strips sensitive strings from chat, screenshots, and logs.

### 2.9 Virtual Desktops, Teach-a-Task Recording, and Live Takeover

Use **Cloud API (`0 MB` extra RAM)** for email, feeds, Telegram, LinkedIn, and public pages. For portals or GUI/SSH workflows with no API, attach a dedicated **Virtual Desktop** (`Details → Computer → Attach Virtual Desktop` or choose **Virtual Desktop** in **Detailed Builder**):

1. **Open the Desktop:** Click **Open Desktop** in the chat header (or **Open Screen** / **Start & Open** in **`Details → Computer`**) to launch the live Fedora XFCE desktop in your browser.
2. **Teach-a-Task by Recording (`Record Session → Stop → Save Skill`):**
   - Click **Record Session** in the desktop toolbar.
   - Perform the browser clicks, logins, navigation, or terminal commands inside XFCE.
   - Click **Stop**, give the recording a name (for example, `Portal Status Check`), and click **Save Skill**. Recorded passwords and Vault values are scrubbed automatically before saving.
3. **Replay via `@` Mention:** Return to the bot's chat, mention the saved Skill and any Vault Secret via **`@`**, and ask it to run the check. Argo executes the steps inside the isolated desktop container and posts **one final post-command Virtual Desktop Snapshot** in chat (hover/click **Save** or **Open Desktop**).
4. **Live Human Takeover:** If a website asks for 2FA, CAPTCHA, or shows an anti-bot challenge, Argo halts without attempting to bypass it and posts **Open Live Desktop**. Sign in manually inside the browser session (cookies persist in `/srv/argo/desktops/<bot_slug>`), then click **Release** in the top-right corner so the bot resumes cleanly.
5. **Automatic RAM Protection:** Host guardrails prevent launching desktops above `80%` host RAM, stop desktops above `90%`, and hibernate idle desktops after `5` minutes.

### 2.10 Real-Life Usage Playbooks

#### Scenario 1: Configure a Feed Monitor by Conversation and Add Two Named Schedules

1. Click **`+ New Bot` → `Quick Setup (Chat)`**, name the bot `Release Watcher`, optionally add `Watch upstream release notes`, and click **Start Onboarding Chat**.
2. Reply in plain English when `Release Watcher` greets you: *"Check `https://news.example.com/feed` every weekday morning, ignore marketing/webinar announcements, and cite source URLs."* The bot updates its instructions and rules immediately.
3. Send: *"Run a test check now on `https://news.example.com/feed` and summarize new entries."* Inspect the cited results in chat.
4. On the attached **`Save as Skill & Named Routine?`** card, set **Routine name** to `Weekday Morning Check`, schedule to `Every weekday at 08:30`, timezone to `America/New_York`, and click **Save Skill & Activate Routine**.
5. Send: *"Keep that weekday check and add a second routine named Monday Digest running Every Monday at 09:00 America/New_York that notifies me even if nothing new arrived."* Open **`Details → Routines`** to inspect both independent schedules and test either one with **`▶`**.

#### Scenario 2: Analyze a Private Uploaded File (`<= 10 MB`) in a Multi-Bot Room

1. Click **`+ New Bot` → `Team Packs`** and click **Install Crew** on **Operations Coordinator Crew**. Argo creates `Operations Lead`, `Source Scout`, `Briefing Writer`, the **Operations Room**, and **Team Hub Board**.
2. Open **Operations Room** in the sidebar.
3. Click **`+`** in the composer (or drag-and-drop) to upload a CSV, PDF, or Markdown report (`<= 10 MB`), type: *"Review the attached Q3 report, check `https://status.example.com`, and draft a concise status update."*, and press **Enter** — or ask an untagged specialist question and watch **Auto-Pick Best Bot** route straight to the right teammate with an **`Auto-picked ...`** badge.
4. Review the **Delegation Plan** card posted by `Operations Lead` and click **`Approve & Run Plan`**. `Source Scout` and `Briefing Writer` execute staged work, posting live progress chips and streaming replies, and `Operations Lead` delivers one combined summary.
5. While `Operations Lead` or another specialist is streaming, queue a quick follow-up without waiting — or click **`■ Stop`** to interrupt mid-run while keeping partial text. Hover `Source Scout`'s reply, click **`↩` Reply**, and ask a targeted follow-up — the Room routes directly to `Source Scout` without waking the other bots.
6. Open **Approvals**, click **Edit** on `Briefing Writer`'s queued update, shorten two lines, and click **Save Rule & Approve** so future drafts adopt your shorter style.

#### Scenario 3: Manage Workspace Activity Side-by-Side with a Docked Board

1. Open any bot chat or Team Room.
2. Type `"can you open the html board"` in the composer and send (or click **Hub Board** in the header, or the dock icon on any Page in the sidebar).
3. Watch **Split View** open the live **Team Hub Board** alongside your conversation. Click a bot card inside the board to trigger a check or jump directly to that bot's thread without leaving Split View.
4. Click **`Details`** in the chat header whenever you need to adjust a bot's apps, secrets, or routines; the inspector slides cleanly over the right side while keeping the board docked underneath.

#### Scenario 4: Teach a Virtual Desktop Portal Check with Zero-AI Vault Credentials

1. Open **Settings → Secrets Vault**, click **New Secret**, enter **Name** `Staging Portal` (`Web Login` with URL, username, password), select **Selected Bots**, pick your desktop bot (`Portal Checker`), and click **Save Secret**.
2. Ensure `Portal Checker` has **Virtual Desktop** enabled (`Details → Computer → Attach Virtual Desktop`), then click **Open Desktop** in the header.
3. Click **Record Session** in the toolbar, sign in or run the portal check in Chromium / `xfce4-terminal`, click **Stop**, name it `Staging Health Check`, and click **Save Skill**.
4. Close the desktop viewer, return to `Portal Checker`'s chat, press **`@`** to pick `Staging Health Check` and `Staging Portal`, and send: *"Run Staging Health Check using Staging Portal and attach the final screen."* Argo injects the encrypted credentials at runtime without showing them to the model and attaches the final desktop snapshot.

### 2.11 Monitoring Activity, Token Budgets, and Diagnostics

- **`Activity` View:** Filter workspace updates by **All Updates**, **Tasks & Handoffs**, or **System Notices**, toggle **Timeline / Workflows**, keep **Hide quiet checks** enabled to collapse unchanged `0`-token polls, or dispatch instructions straight to `@Bot` from the top bar.
- **`Settings → Models & Usage`:** Monitor **Today's Usage**, **This Month**, **0-Token Smart Checks** saved, and **Usage by Bot & Routine**. Enforce daily token limits or monthly USD caps per provider, downgrade heavy bots with **Switch to Gemini 3.8 Flash**, or pause noisy schedules with **Pause Bot**.
- **`Settings → Diagnostics` (`Details → More Options → View Run Logs`):** Inspect exact **Run Traces** (model, tokens, timing, tool calls, errors) and severity-filtered **System Logs** with automatic secret scrubbing.

---

## Reference Documentation

- [`compose.yml`](compose.yml) — Single-host container stack and environment configuration
- [`Dockerfile`](Dockerfile) — Multi-stage Fedora 45 build (`Node 26` frontend + `Python 3.15` runtime)
