import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const directory = path.dirname(fileURLToPath(import.meta.url));
const stateDirectory = process.env.LOCAL_CD_STATE_DIR ?? path.join(directory, '..', 'artifacts', 'local-cd-agent');
const owner = 'Sera5imSec';
const projects = {eks: 'eks-boundary-matrix-ci', realworld: 'realworld-appsec-ci'};
const command = process.argv[2] ?? 'once';
const wanted = process.argv[3] ?? 'all';
const selected = wanted === 'all' ? Object.keys(projects) : [wanted];
if (selected.some(project => !projects[project])) throw new Error('Unknown project');
fs.mkdirSync(path.join(stateDirectory, 'artifacts'), {recursive: true});
const statePath = path.join(stateDirectory, 'state.json');

function token() {
  const result = spawnSync('git', ['credential', 'fill'], {
    input: `protocol=https\nhost=github.com\nusername=${owner}\n\n`, encoding: 'utf8',
    env: {...process.env, GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never'}
  });
  if (result.status !== 0) throw new Error('Existing GitHub credential unavailable');
  const password = result.stdout.split(/\r?\n/).find(row => row.startsWith('password='))?.slice(9);
  if (!password) throw new Error('No GitHub credential');
  return password;
}

function linux(file) {
  const absolute = path.resolve(file).replaceAll('\\', '/');
  if (!/^[A-Za-z]:\//.test(absolute)) throw new Error('Expected an absolute Windows path');
  return '/mnt/' + absolute[0].toLowerCase() + absolute.slice(2);
}

async function checksum(file) {
  const hash = createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function cycle() {
  const headers = {Authorization: 'Bearer ' + token(), Accept: 'application/vnd.github+json',
    'User-Agent': 'boundary-local-cd', 'X-GitHub-Api-Version': '2022-11-28'};
  async function api(route, method = 'GET', body) {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const response = await fetch('https://api.github.com' + route, {method, headers: {...headers,
          ...(body ? {'Content-Type': 'application/json'} : {})}, body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(30000)});
        if (!response.ok) throw new Error(`GitHub HTTP ${response.status} ${route}`);
        return response.status === 204 ? null : await response.json();
      } catch (error) {
        if (attempt === 2) throw new Error(route + ': ' + (error.cause?.message ?? error.message));
        await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
  }
  if ((await api('/user')).login !== owner) throw new Error('Wrong GitHub account');
  const state = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : {};
  for (const project of selected) {
    const repository = owner + '/' + projects[project];
    const root = '/repos/' + repository;
    const repo = await api(root);
    if (repo.full_name !== repository || project === 'eks' && !repo.private) throw new Error('Unexpected repository identity');
    const main = await api(root + '/commits/main');
    if (command === 'status') {
      console.log(JSON.stringify({project, main: main.sha, installed: state[project] ?? null}));
      continue;
    }
    const runs = (await api(root + '/actions/workflows/cd.yml/runs?branch=main&per_page=30')).workflow_runs;
    const run = runs.find(value => value.status === 'completed' && value.conclusion === 'success' && value.head_sha === main.sha);
    if (!run || state[project]?.delivery_run_id === run.id) continue;
    const ciRuns = (await api(root + '/actions/workflows/ci.yml/runs?head_sha=' + main.sha + '&per_page=30')).workflow_runs;
    const ci = ciRuns.find(value => value.head_branch === 'main' && ['push', 'workflow_dispatch'].includes(value.event));
    if (!ci || ci.status !== 'completed' || ci.conclusion !== 'success') continue;
    const artifacts = (await api(root + '/actions/runs/' + run.id + '/artifacts')).artifacts
      .filter(value => value.name === 'local-cd-image' && !value.expired);
    if (artifacts.length !== 1 || artifacts[0].size_in_bytes > 750 * 1024 * 1024) throw new Error('Invalid delivery artifact');
    const archive = path.join(stateDirectory, 'artifacts', project + '-' + run.id + '.zip');
    const expectedDigest = artifacts[0].digest?.replace(/^sha256:/, '');
    if (!/^[0-9a-f]{64}$/.test(expectedDigest ?? '')) throw new Error('GitHub artifact digest is missing');
    let cached = fs.existsSync(archive) && fs.statSync(archive).size === artifacts[0].size_in_bytes &&
      await checksum(archive) === expectedDigest;
    const partial = archive + '.partial';
    if (!cached && fs.existsSync(partial) && fs.statSync(partial).size === artifacts[0].size_in_bytes &&
        await checksum(partial) === expectedDigest) {
      fs.renameSync(partial, archive);
      cached = true;
    }
    if (!cached) {
      const offset = fs.existsSync(partial) ? fs.statSync(partial).size : 0;
      const response = await fetch('https://api.github.com' + root + '/actions/artifacts/' + artifacts[0].id + '/zip',
        {headers: {...headers, ...(offset ? {Range: 'bytes=' + offset + '-'} : {})}, signal: AbortSignal.timeout(900000)});
      if (!response.ok) throw new Error('Artifact download failed');
      const resumed = response.status === 206 && response.headers.get('content-range')?.startsWith('bytes ' + offset + '-');
      const file = fs.openSync(partial, resumed ? 'a' : 'w');
      let bytes = resumed ? offset : 0;
      try {
        for await (const chunk of response.body) {
          bytes += chunk.length;
          if (bytes > artifacts[0].size_in_bytes) throw new Error('Artifact exceeds its declared size');
          fs.writeSync(file, chunk);
        }
      } finally { fs.closeSync(file); }
      if (bytes !== artifacts[0].size_in_bytes || await checksum(partial) !== expectedDigest) {
        fs.unlinkSync(partial);
        throw new Error('Downloaded GitHub artifact digest does not match');
      }
      fs.renameSync(partial, archive);
    }
    if ((await api(root + '/commits/main')).sha !== main.sha) continue;
    const deployment = await api(root + '/deployments', 'POST', {ref: main.sha, environment: 'local-cd',
      auto_merge: false, required_contexts: [], description: 'Loopback-only local Docker test stand',
      payload: {delivery_run_id: run.id, ci_run_id: ci.id}});
    if (!deployment.id) throw new Error('Deployment record was not created');
    const statusPath = root + '/deployments/' + deployment.id + '/statuses';
    await api(statusPath, 'POST', {state: 'in_progress', log_url: run.html_url, environment: 'local-cd'});
    try {
      const result = spawnSync('wsl', ['-d', 'DifyAudit', '-u', 'root', '--', 'python3', linux(path.join(directory, 'deploy.py')),
        '--project', project, '--revision', main.sha, '--archive', linux(archive),
        '--ci-run', String(ci.id), '--delivery-run', String(run.id)],
        {encoding: 'utf8', windowsHide: true, timeout: 300000, maxBuffer: 2 * 1024 * 1024});
      if (result.status !== 0) throw new Error('Local installation failed: ' + (result.stdout?.trim() || result.stderr?.trim() || 'unknown error'));
      const observation = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
      if (observation.status !== 'DEPLOYED' || observation.revision !== main.sha) throw new Error('Unexpected installation result');
      await api(statusPath, 'POST', {state: 'success', log_url: run.html_url, environment: 'local-cd',
        environment_url: observation.url, description: 'Installed image passed its HTTP check'});
      state[project] = {...observation, delivery_run_id: run.id, ci_run_id: ci.id, deployment_id: deployment.id,
        installed_at: new Date().toISOString()};
      fs.writeFileSync(statePath, JSON.stringify(state, null, 2) + '\n');
      console.log(JSON.stringify(state[project]));
    } catch (error) {
      await api(statusPath, 'POST', {state: 'failure', log_url: run.html_url, environment: 'local-cd',
        description: 'Local installation failed; inspect the local agent log'});
      throw error;
    }
  }
}

if (command === 'watch') {
  const lockPath = path.join(stateDirectory, 'agent.lock');
  const lock = fs.openSync(lockPath, 'wx');
  fs.writeSync(lock, String(process.pid));
  const finish = () => {fs.closeSync(lock); fs.unlinkSync(lockPath); process.exit();};
  process.once('SIGINT', finish);
  process.once('SIGTERM', finish);
  for (;;) {
    try { await cycle(); } catch (error) { console.error(new Date().toISOString() + ' ' + error.message); }
    await new Promise(resolve => setTimeout(resolve, 60000));
  }
} else if (['once', 'status'].includes(command)) {
  await cycle();
} else throw new Error('Use once, watch or status');
