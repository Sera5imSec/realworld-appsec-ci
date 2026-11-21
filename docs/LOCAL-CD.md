# RealWorld local CD

The project has two delivery targets:

**Local CD** builds the current main application only after successful normal CI, then delivers its Docker image to the local test stand. The existing 32 application matrices and their 164 scenarios remain unchanged.

```text
Push/merge main → CI succeeds → Local CD verifies exact CI revision
→ image build → real HTTP smoke check → immutable Actions artifact
→ local pull agent checks main, CI, archive checksum and image labels
→ candidate starts on an isolated port → health check
→ current container is replaced → health check → GitHub Deployment status
```

The Actions run produces the delivery artifact; the actual installation result appears under GitHub environment **local-cd**. A green build alone is not an installation result.

The local agent runs on Windows with Node 22, Windows Git Credential Manager and Docker/Python 3.11+ in the `DifyAudit` WSL distribution. It never registers a self-hosted Actions runner and uses the existing account credential in memory. Start only one watcher for both repositories:

```powershell
$env:LOCAL_CD_STATE_DIR = 'C:\path\to\local-cd-state'
node --use-system-ca delivery/agent.mjs once
node --use-system-ca delivery/agent.mjs watch
```

Keep the computer, WSL Docker and watcher running. After reboot, restart the watcher. `once` performs one delivery check; `status` prints installed revisions. Polling is once per minute. No automatic Windows startup task is installed.

The backend is served locally at **http://localhost:18082/api/ping/**. It runs in release mode with a generated JWT key. SQLite lives outside the image at `/var/lib/boundary-local-cd/realworld/data/gorm.db`; candidate validation uses a separate snapshot. Updates and failed promotions preserve the database.

The installer runs containers as non-root, drops capabilities, uses a read-only root filesystem and publishes only loopback ports. It accepts only the approved repository, exact main revision and archive/image identities. It rejects unsuccessful, scheduled or PR CI, stale revisions and corrupted artifacts. Candidate failure keeps the current version; promotion failure restores the previous container. All local deployment files belong to `/var/lib/boundary-local-cd/realworld`.

Normal CI runs admission tests for this delivery path. The admission tests reject unsuccessful CI, another revision or repository, PR events, schedules and an unrelated workflow. Source mutation sensitivity remains a separate manually dispatched workflow.

For an explicit installer integration check, use `delivery/check_install.py` with the two fixture images described in that script. It performs real Docker updates and checks checksum rejection, promotion rollback and RealWorld database persistence. It is outside the automatic unit-test discovery pattern.

The trigger uses GitHub's [workflow_run event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run), then independently verifies the source commit's CI through the Actions API.
