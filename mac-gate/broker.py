#!/usr/bin/env python3
"""Privileged Mac-side VRChat production authorization and deployment broker.

Installed OUTSIDE the repository, writable only by a Mac administrator.
Reads one JSON request from stdin: {oidc_token, reservation_issue}.
Never trusts paths, SHAs, actor names, or Blueprint IDs supplied by the caller.
Only the broker account owns production VRCLI session and the private worktree.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import jwt

POLICY_PATH = Path('/opt/vrchat-prod/policy.json')
SECRETS_PATH = Path('/opt/vrchat-prod/secrets.json')
LOCK_PATH = Path('/opt/vrchat-prod/deployment.lock')
RECEIPT_DIRECTORY = Path('/opt/vrchat-prod/receipts')
WORLD_RE = re.compile(r'^wrld_[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
SHA_RE = re.compile(r'^[a-f0-9]{40}$')
ISSUE_PREFIX = 'VRCHAT_PRODUCTION_RESERVATION_V4\n'
LABEL = 'vrchat-prod-v4'
DISPATCHED = 'vrchat-prod-v4-dispatched'
GITHUB_ISSUER = 'https://token.actions.githubusercontent.com'
JWKS_URL = GITHUB_ISSUER + '/.well-known/jwks'
SOURCE_DIRS = ('Assets', 'Packages', 'ProjectSettings')
EXPECTED_EXECUTE = '.github/workflows/vrchat-prod-execute.yml'
EXPECTED_RESERVE = '.github/workflows/vrchat-prod-reserve.yml'
TEST_WORKFLOW = 'vrchat-test-develop.yml'


def must(condition, message):
    if not condition:
        raise PermissionError(message)


def read_json(path: Path):
    # No variable path supplied by request; no caller-controlled lookup.
    if path.is_symlink():
        raise PermissionError(f'Config may not be a symlink: {path}')
    stat = path.stat()
    must(stat.st_uid in (0, os.geteuid()), f'Unsafe owner on {path}')
    must((stat.st_mode & 0o022) == 0, f'Writable by group/others: {path}')
    with path.open(encoding='utf-8') as file:
        return json.load(file)


def validate_config(policy, secrets):
    required = ('repository', 'repository_id', 'allowed_actor_ids', 'production_world_ids',
                'test_world_ids', 'worktree', 'remote_url', 'vrcli_account', 'oidc_audience')
    for key in required:
        must(policy.get(key), f'Missing Mac policy: {key}')
    must(isinstance(policy['repository_id'], int) and policy['repository_id'] > 0,
         'repository_id must be an integer from GitHub API')
    must(all(isinstance(i, int) and i > 0 for i in policy['allowed_actor_ids']),
         'allowed_actor_ids must contain numeric GitHub user IDs')
    must(bool(policy['allowed_actor_ids']), 'There must be at least one operator')
    must(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', policy['repository']),
         'Invalid repository name')
    must(policy['oidc_audience'] == 'urn:vrchat:prod:' + policy['repository'],
         'Invalid GitHub OIDC audience')
    for key in ('test_world_ids', 'production_world_ids'):
        must(isinstance(policy[key], list) and policy[key], f'{key} must be a nonempty list')
        must(all(isinstance(w, str) and WORLD_RE.fullmatch(w) for w in policy[key]),
             f'Invalid IDs in {key}')
    must(not set(policy['production_world_ids']) & set(policy['test_world_ids']),
         'Test and production world IDs overlap')
    must(Path(policy['worktree']).is_absolute(), 'Worktree must be absolute')
    must(policy['worktree'].startswith('/Users/') or policy['worktree'].startswith('/opt/'),
         'Worktree must be in the dedicated user home or /opt')
    must(secrets.get('github_read_token'), 'Missing dedicated GitHub read token')
    must(len(secrets.get('queue_signing_key', '')) >= 32, 'Missing HMAC queue signing key')
    return True


class GitHub:
    def __init__(self, policy, secrets):
        self.repo = policy['repository']
        self.token = secrets['github_read_token']
        self.root = '/repos/' + self.repo

    def get(self, path):
        url = 'https://api.github.com' + (path if path.startswith('/repos/') else self.root + path)
        req = urllib.request.Request(url, headers={
            'Authorization': 'Bearer ' + self.token,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'vrchat-mac-production-broker'})
        try:
            with urllib.request.urlopen(req, timeout=25) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise PermissionError(f'GitHub API denied {path} (HTTP {exc.code})') from None

    def pages(self, path, key=None, maxpages=5):
        items = []
        for page in range(1, maxpages + 1):
            sep = '&' if '?' in path else '?'
            response = self.get(f'{path}{sep}per_page=100&page={page}')
            batch = response[key] if key else response
            must(isinstance(batch, list), 'Invalid GitHub list response')
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise PermissionError('Too many results; raise pagination limit explicitly')


def verify_oidc(encoded, policy):
    must(isinstance(encoded, str) and len(encoded) < 20000 and encoded.count('.') == 2,
         'Malformed GitHub OIDC token')
    jwks = jwt.PyJWKClient(JWKS_URL)
    key = jwks.get_signing_key_from_jwt(encoded)
    claims = jwt.decode(encoded, key.key, algorithms=['RS256'], issuer=GITHUB_ISSUER,
                        audience=policy['oidc_audience'], options={'require': ['exp', 'iat', 'iss', 'aud']},
                        leeway=30)
    # Use stable IDs and exact workflow identity, never an untrusted actor string.
    must(str(claims.get('repository_id')) == str(policy['repository_id']), 'Wrong GitHub repository ID')
    must(claims.get('repository') == policy['repository'], 'Wrong repository')
    must(claims.get('ref') == 'refs/heads/release', 'Not running from release')
    must(claims.get('event_name') == 'workflow_dispatch', 'Unexpected workflow event')
    must(claims.get('workflow_ref') ==
         f"{policy['repository']}/{EXPECTED_EXECUTE}@refs/heads/release", 'Wrong workflow_ref')
    must(claims.get('environment') == 'vrchat-production', 'Production environment was not used')
    must(str(claims.get('run_id', '')).isdigit(), 'OIDC run ID is missing')
    return claims


def verified_queue_issue(issue, policy, secrets):
    must((issue.get('user') or {}).get('login') == 'github-actions[bot]', 'Queue Issue must be bot-authored')
    must(issue.get('state') == 'closed', 'Queue Issue not claimed by scheduler')
    ls = {(l.get('name') if isinstance(l, dict) else l) for l in issue.get('labels', [])}
    must({LABEL, DISPATCHED}.issubset(ls), 'Queue Issue is not dispatched')
    body = issue.get('body') or ''
    must(body.startswith(ISSUE_PREFIX), 'Unexpected queue schema')
    record = json.loads(body[len(ISSUE_PREFIX):])
    received = record.pop('signature', None)
    message = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    expected = hmac.new(secrets['queue_signing_key'].encode('utf-8'), message, hashlib.sha256).hexdigest()
    must(isinstance(received, str) and hmac.compare_digest(received, expected), 'Queue signature invalid')
    must(record.get('schema') == 4 and record.get('repository') == policy['repository'],
         'Queue repository/schema mismatch')
    sha = record.get('release_sha')
    world = record.get('production_world_id')
    must(isinstance(sha, str) and SHA_RE.fullmatch(sha), 'Malformed release SHA')
    must(isinstance(world, str) and WORLD_RE.fullmatch(world), 'Malformed World ID')
    must(world in policy['production_world_ids'] and world not in policy['test_world_ids'],
         'World ID not allowed by Mac-side policy')
    due = dt.datetime.fromisoformat(record['scheduled_at_jst'])
    must(due.utcoffset() == dt.timedelta(hours=9), 'Queue date must be JST')
    must(due <= dt.datetime.now(dt.timezone.utc), 'Deployment time has not arrived')
    must(isinstance(record.get('request_run_id'), int), 'Reservation source run missing')
    return record


def verify_booking_actor(gh, record, policy):
    # Look up GitHub's own run actor; requested_by in the queue is not authoritative.
    run = gh.get('/actions/runs/' + str(record['request_run_id']))
    must(run.get('event') == 'workflow_dispatch' and run.get('conclusion') == 'success',
         'Reservation workflow has not completed successfully')
    must(run.get('path', '').lstrip('/') == EXPECTED_RESERVE,
         'Reservation was created by an unexpected workflow')
    must(run.get('head_branch') == 'release' and run.get('head_sha') == record['release_sha'],
         'Reservation run was not for the pinned release commit')
    actor = run.get('triggering_actor') or run.get('actor') or {}
    # Actor who originally started the run, NOT who re-ran it later.
    actor = run.get('actor') or actor
    must(isinstance(actor.get('id'), int) and actor['id'] in policy['allowed_actor_ids'],
         'Original reservation operator is NOT allowed on Mac mini')
    must((actor.get('login') or '').lower() == record.get('requested_by', '').lower(),
         'Signed queue requester does not match GitHub run actor')
    return actor


def verify_execute_run(gh, claims):
    run = gh.get('/actions/runs/' + str(claims['run_id']))
    must(run.get('path', '').lstrip('/') == EXPECTED_EXECUTE,
         'OIDC run does not belong to deployment workflow')
    must(run.get('event') == 'workflow_dispatch', 'Deployment run event mismatch')
    must(run.get('head_branch') == 'release', 'Deploy run branch mismatch')
    must(str(run.get('id')) == str(claims['run_id']), 'Deploy run ID mismatch')


def verify_release(gh, record):
    sha = record['release_sha']
    comparison = gh.get('/compare/' + sha + '...release')
    must(comparison.get('status') in ('ahead', 'identical'), 'Release commit is not in release')
    prs = gh.pages('/commits/' + sha + '/pulls')
    candidates = [x for x in prs if x.get('number') == record['pr_number']
                  and x.get('merged_at') and (x.get('base') or {}).get('ref') == 'release']
    must(len(candidates) == 1, 'Pinned release commit has no matching merged PR')
    pr = gh.get('/pulls/' + str(record['pr_number']))
    must(pr.get('merged') and pr.get('merge_commit_sha') == sha, 'Release PR merge SHA mismatch')
    must(pr['head']['sha'] == record['test_sha'], 'Test SHA no longer matches the merged PR')
    must(pr['head']['ref'] == 'develop', 'Merged PR does not originate from develop')
    reviews = gh.pages('/pulls/' + str(pr['number']) + '/reviews')
    latest = {}
    for rev in reviews:
        usr = (rev.get('user') or {}).get('login', '').lower()
        if usr and usr != (pr.get('user') or {}).get('login', '').lower() and rev.get('state') in ('APPROVED','CHANGES_REQUESTED','DISMISSED'):
            latest[usr] = (rev['state'], rev.get('commit_id'))
    must(any(state == 'APPROVED' and approved_sha == record['test_sha'] for state,approved_sha in latest.values()),
         'Current PR-head approval not found')
    runs = gh.pages('/actions/workflows/' + TEST_WORKFLOW + '/runs?branch=develop&event=push&head_sha=' + record['test_sha'], 'workflow_runs')
    must(any(run.get('event') == 'push' and run.get('head_branch') == 'develop'
             and run.get('head_sha') == record['test_sha'] and run.get('conclusion') == 'success' for run in runs),
         'No successful deploy to test for this exact SHA')
    trees = []
    for commit_sha in (record['test_sha'], sha):
        git_commit = gh.get('/git/commits/' + commit_sha)
        tree = gh.get('/git/trees/' + git_commit['tree']['sha'])
        mapping = {x.get('path'):x.get('sha') for x in tree.get('tree', []) if x.get('type')=='tree'}
        must(all(x in mapping for x in SOURCE_DIRS), 'Missing Unity source tree in release')
        trees.append(tuple(mapping[x] for x in SOURCE_DIRS))
    must(trees[0] == trees[1], 'Production Unity sources differ from test-deployed sources')


def execute(cmd, *, cwd=None, env=None, timeout=None):
    print('Command:', ' '.join(cmd[:3]) + (' ...' if len(cmd) > 3 else ''), flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True, timeout=timeout)


def deployment(policy, record):
    workspace = Path(policy['worktree']).resolve(strict=True)
    must(workspace.is_dir() and (workspace/'.git').exists(), 'Dedicated production worktree not initialized')
    expected_remote = policy['remote_url']
    remote = subprocess.check_output(['git', '-C', str(workspace), 'remote', 'get-url', 'origin'], text=True).strip()
    must(remote == expected_remote, 'Production Git remote differs from Mac policy')
    execute(['git', 'fetch', '--no-tags', 'origin', '+refs/heads/release:refs/remotes/origin/release'], cwd=workspace, timeout=300)
    sha = record['release_sha']
    execute(['git', 'merge-base', '--is-ancestor', sha, 'refs/remotes/origin/release'],cwd=workspace,timeout=30)
    execute(['git', 'checkout', '--force', '--detach', sha], cwd=workspace, timeout=120)
    execute(['git', 'lfs', 'pull'], cwd=workspace, timeout=600)
    must((workspace/'Assets/_Rin/Scene/VRCli_Test.unity').is_file(), 'Production Unity Scene missing')
    environment = os.environ.copy()
    environment['PATH'] = '/opt/homebrew/bin:' + str(Path.home()/'.dotnet/tools') + ':' + environment.get('PATH','')
    base = ['--login', policy['vrcli_account'], '--project', str(workspace),
            '--scene', 'Assets/_Rin/Scene/VRCli_Test.unity', '--blueprint', record['production_world_id'],
            '--platform', 'StandaloneWindows64']
    execute(['vrcli','check',*base,'--plain'], cwd=workspace,env=environment,timeout=3600)
    execute(['vrcli','deploy',*base,'--yes','--plain'], cwd=workspace,env=environment,timeout=7200)


def main():
    policy, secrets = read_json(POLICY_PATH), read_json(SECRETS_PATH)
    validate_config(policy, secrets)
    if sys.argv[1:] == ['--check-config']:
        print('Mac production authorization policy: VALID (no upload)')
        return
    must(sys.argv[1:] == [], 'No CLI override parameters are supported')
    req = json.load(sys.stdin)
    must(isinstance(req, dict) and set(req) == {'oidc_token','reservation_issue'},
         'Request must contain exactly oidc_token and reservation_issue')
    num = req['reservation_issue']
    must(str(num).isdigit() and 0 < int(num) < 2**31, 'Invalid queue Issue number')
    claims = verify_oidc(req['oidc_token'], policy)
    gh = GitHub(policy, secrets)
    verify_execute_run(gh, claims)
    issue = gh.get('/issues/' + str(num))
    record = verified_queue_issue(issue, policy, secrets)
    verify_booking_actor(gh, record, policy)
    verify_release(gh, record)
    # A separate OS account owns a persistent, non-repository lock.
    with LOCK_PATH.open('a+',encoding='utf-8') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        verify_booking_actor(gh, record, policy)  # Check again immediately before starting.
        must(RECEIPT_DIRECTORY.is_dir() and not RECEIPT_DIRECTORY.is_symlink(),
             'Protected receipt directory is not configured')
        receipt = RECEIPT_DIRECTORY / (str(num) + '.json')
        # Permanent single-use record, created atomically before initiating any upload.
        # An admin must investigate failures; reruns cannot silently redeploy.
        try:
            fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise PermissionError('Reservation already consumed by Mac mini; refusing replay') from None
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump({'reservation_issue': int(num), 'run_id': str(claims['run_id']),
                       'sha': record['release_sha'], 'world': record['production_world_id'],
                       'started_at': dt.datetime.now(dt.timezone.utc).isoformat()}, out)
        print(f"MAC AUTHORIZED: queue #{num}, world {record['production_world_id']}, SHA {record['release_sha']}", flush=True)
        deployment(policy, record)
    print('MAC PROD DEPLOY SUCCESS',flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('MAC PROD DEPLOY DENIED/FAILED: ' + str(exc),file=sys.stderr,flush=True)
        sys.exit(1)
