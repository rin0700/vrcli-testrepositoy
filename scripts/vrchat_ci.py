#!/usr/bin/env python3
"""VRChat release gate and signed production reservation controller (stdlib only).

This script runs from the trusted default branch, not from an unreviewed PR.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

WORLD_RE = re.compile(r'^wrld_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
SHA_RE = re.compile(r'^[0-9a-f]{40}$')
ISSUE_PREFIX = 'VRCHAT_PRODUCTION_RESERVATION_V4\n'
LABEL = 'vrchat-prod-v4'
DISPATCHED = 'vrchat-prod-v4-dispatched'
JST = dt.timezone(dt.timedelta(hours=9))
TEST_WORKFLOW = 'vrchat-test-develop.yml'
EXECUTE_WORKFLOW = 'vrchat-prod-execute.yml'
SOURCES = ('Assets', 'Packages', 'ProjectSettings')


def require(name):
    value = os.environ.get(name, '').strip()
    if not value:
        raise ValueError('Missing configuration: ' + name)
    return value


def api(method, path, payload=None):
    data = None if payload is None else json.dumps(payload, separators=(',', ':')).encode('utf-8')
    url = os.getenv('GITHUB_API_URL', 'https://api.github.com').rstrip('/') + path
    request = urllib.request.Request(url, data=data, method=method, headers={
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + require('GH_TOKEN'),
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
        'User-Agent': 'vrchat-ci-v4'})
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            return json.loads(response.read() or b'{}')
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'GitHub API {method} {path} -> {exc.code}: {exc.read().decode(errors="replace")[:250]}') from None


def repo():
    return require('GITHUB_REPOSITORY')


def gh(path):
    return '/repos/' + repo() + path


def get_pages(path, key=None, limit=10):
    output = []
    for page in range(1, limit + 1):
        sep = '&' if '?' in path else '?'
        obj = api('GET', path + f'{sep}page={page}&per_page=100')
        batch = obj[key] if key else obj
        output.extend(batch)
        if len(batch) < 100:
            return output
    raise ValueError('GitHub API pagination limit exceeded')


def world(value):
    value = str(value).strip().lower()
    if not WORLD_RE.fullmatch(value):
        raise ValueError('Invalid VRChat world ID: ' + value)
    return value


def commit(value):
    value = str(value).strip().lower()
    if not SHA_RE.fullmatch(value):
        raise ValueError('Expected full 40-character git SHA')
    return value


def allowset(value):
    return {i.lower() for i in re.split(r'[\s,]+', value or '') if i.strip()}


def operator(login):
    if (login or '').lower() not in allowset(require('VRC_DEPLOY_OPERATORS')):
        raise ValueError('Not an authorized production operator: ' + str(login))


def target_world(value):
    target = world(value)
    if target not in {world(i) for i in allowset(require('VRC_PROD_ALLOWED_IDS'))}:
        raise ValueError('Production world ID is not allowlisted')
    if target in {world(i) for i in allowset(require('VRC_TEST_ALLOWED_IDS'))}:
        raise ValueError('Production and test worlds must not overlap')
    return target


def schedule(value, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    value = value.strip()
    if value.upper() == 'NOW':
        return now.astimezone(JST)
    if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d', value):
        raise ValueError('Enter NOW or YYYY-MM-DDTHH:MM (JST)')
    parsed = dt.datetime.strptime(value, '%Y-%m-%dT%H:%M').replace(tzinfo=JST)
    if parsed < now.astimezone(JST) - dt.timedelta(minutes=1):
        raise ValueError('Scheduled time is in the past')
    if parsed > now.astimezone(JST) + dt.timedelta(days=180):
        raise ValueError('Maximum reservation period: 180 days')
    return parsed


def test_deployed(test_sha):
    sha = commit(test_sha)
    runs = get_pages(gh(f'/actions/workflows/{TEST_WORKFLOW}/runs?branch=develop&event=push&head_sha={sha}'), 'workflow_runs', limit=3)
    return any(r.get('head_sha', '').lower() == sha and r.get('conclusion') == 'success'
               and r.get('event') == 'push' and r.get('head_branch') == 'develop' for r in runs)


def source_trees(sha):
    sha = commit(sha)
    git_commit = api('GET', gh(f'/git/commits/{sha}'))
    data = api('GET', gh('/git/trees/' + git_commit['tree']['sha']))
    byname = {x.get('path'): x.get('sha') for x in data['tree'] if x.get('type') == 'tree'}
    for root in SOURCES:
        if not byname.get(root):
            raise ValueError(f'Missing source directory {root} in {sha}')
    return tuple(byname[root] for root in SOURCES)


def require_same_world_source(tested_sha, production_sha):
    if source_trees(tested_sha) != source_trees(production_sha):
        raise ValueError('Release world source differs from the tested develop commit')


def get_release_pull(release_sha):
    release_sha = commit(release_sha)
    prs = get_pages(gh(f'/commits/{release_sha}/pulls'), limit=3)
    possible = [p for p in prs
                if p.get('merged_at') and p.get('base', {}).get('ref') == 'release'
                and p.get('head', {}).get('ref') == 'develop'
                and p.get('head', {}).get('repo', {}).get('full_name', '').lower() == repo().lower()]
    for candidate in possible:
        pr = api('GET', gh('/pulls/' + str(candidate['number'])))
        if (pr.get('merged') and pr.get('merge_commit_sha', '').lower() == release_sha
                and pr.get('base', {}).get('ref') == 'release'):
            return pr
    raise ValueError('Release commit must be the merge/squash result of a develop -> release PR')


def approved(pr):
    reviews = get_pages(gh('/pulls/' + str(pr['number']) + '/reviews'), limit=10)
    latest = {}
    for r in reviews:
        user = (r.get('user') or {}).get('login', '').lower()
        if (user and user != (pr.get('user') or {}).get('login', '').lower()
                and r.get('state') in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED')):
            # Ignore COMMENTED review entries; a later comment doesn't revoke approval.
            latest[user] = (r.get('state'), r.get('commit_id'))
    if not any(state == 'APPROVED' and sha == pr['head']['sha']
               for state, sha in latest.values()):
        raise ValueError('Release PR has no current-head approval from another reviewer')


def release_ancestor(sha):
    # Compare base SHA against release tip; ahead/identical means release contains SHA.
    data = api('GET', gh('/compare/' + commit(sha) + '...release'))
    if data.get('status') not in ('ahead', 'identical'):
        raise ValueError('Pinned release SHA is not an ancestor of release')


def verify_release(sha, check_tip=False):
    sha = commit(sha)
    release_ancestor(sha)
    if check_tip:
        tip = api('GET', gh('/branches/release'))['commit']['sha'].lower()
        if tip != sha:
            raise ValueError('release changed since Actions was started. Rerun to pin its current tip.')
    pr = get_release_pull(sha)
    approved(pr)
    test_sha = commit(pr['head']['sha'])
    if not test_deployed(test_sha):
        raise ValueError('PR head commit was not successfully uploaded to test world by develop push')
    require_same_world_source(test_sha, sha)
    return {'pr_number': pr['number'], 'test_sha': test_sha}


def signing_key():
    key = require('VRC_QUEUE_SIGNING_KEY').encode('utf-8')
    if len(key) < 32:
        raise ValueError('VRC_QUEUE_SIGNING_KEY must be at least 32 characters')
    return key


def digest(data):
    plain = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return hmac.new(signing_key(), plain, hashlib.sha256).hexdigest()


def issue_data(issue):
    if (issue.get('user') or {}).get('login') != 'github-actions[bot]':
        return None
    body = issue.get('body') or ''
    if not body.startswith(ISSUE_PREFIX):
        return None
    try:
        data = json.loads(body[len(ISSUE_PREFIX):])
        signature = data.pop('signature')
        if not hmac.compare_digest(signature, digest(data)) or data.get('schema') != 4:
            return None
        if data.get('repository') != repo():
            return None
        commit(data['release_sha'])
        world(data['production_world_id'])
        due = dt.datetime.fromisoformat(data['scheduled_at_jst'])
        if due.utcoffset() != dt.timedelta(hours=9):
            return None
        data['_due'] = due
        return data
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return None


def issue_path(number):
    if not re.fullmatch(r'[1-9][0-9]*', str(number)):
        raise ValueError('Issue number must be a positive integer')
    return gh('/issues/' + str(number))


def issues(state='open'):
    query = urllib.parse.urlencode({'state': state, 'labels': LABEL})
    return [i for i in get_pages(gh('/issues?' + query), limit=10)
            if 'pull_request' not in i and issue_data(i)]


def labels(issue):
    return {x['name'] for x in issue.get('labels', [])}


def ensure_label(name, color, description):
    try:
        api('POST', gh('/labels'), {'name': name, 'color': color, 'description': description})
    except RuntimeError as exc:
        if '-> 422:' not in str(exc):
            raise
        api('GET', gh('/labels/' + urllib.parse.quote(name)))


def print_output(name, value):
    with open(require('GITHUB_OUTPUT'), 'a', encoding='utf-8') as file:
        file.write(f'{name}={value}\n')


def pr_gate():
    head = commit(require('PR_HEAD_SHA'))
    if require('PR_HEAD_REPO').lower() != repo().lower() or require('PR_HEAD_REF') != 'develop':
        raise ValueError('Only same-repository develop -> release PRs are eligible')
    if not test_deployed(head):
        raise ValueError('This PR head SHA has not yet passed the develop test upload')
    # The workflow separately compares PR merge source dirs to this SHA using git diff.
    print('Test upload verified for develop SHA:', head)


def reserve():
    if require('GITHUB_REF') != 'refs/heads/release':
        raise ValueError('Production reservations can only run from release')
    operator(require('GITHUB_ACTOR'))
    target = target_world(require('PRODUCTION_WORLD_ID'))
    release_sha = commit(require('GITHUB_SHA'))
    d = verify_release(release_sha, check_tip=True)
    when = schedule(require('SCHEDULED_AT_JST'))
    data = {'schema': 4, 'repository': repo(), 'release_sha': release_sha,
            'test_sha': d['test_sha'], 'pr_number': d['pr_number'],
            'production_world_id': target,
            'scheduled_at_jst': when.isoformat(timespec='minutes'),
            'requested_by': require('GITHUB_ACTOR'),
            'request_run_id': int(require('GITHUB_RUN_ID'))}
    ensure_label(LABEL, '0969da', 'Signed VRChat production reservation v4')
    ensure_label(DISPATCHED, '8250df', 'Production upload already dispatched')
    # Deduplicate exact re-runs of booking even if original issue already closed.
    for original in issues(state='all'):
        prior = issue_data(original)
        if prior and prior['request_run_id'] == data['request_run_id']:
            print('Already reserved as issue #', original['number'])
            return
    signed = dict(data, signature=digest(data))
    resp = api('POST', gh('/issues'), {
        'title': f'[VRChat PROD v4] {target} / {when.strftime("%Y-%m-%d %H:%M JST")} / {release_sha[:12]}',
        'body': ISSUE_PREFIX + json.dumps(signed, sort_keys=True, ensure_ascii=False),
        'labels': [LABEL]})
    print('Created production reservation:', resp['html_url'])
    print_output('reservation_issue', resp['number'])


def poll():
    # Queued work is claimed before self-hosted runner is occupied.
    ready = sorted((issue_data(i)['_due'], i['number'], i) for i in issues()
                   if DISPATCHED not in labels(i) and issue_data(i)['_due'] <= dt.datetime.now(JST))
    for _, number, i in ready:
        api('POST', issue_path(number) + '/labels', {'labels': [DISPATCHED]})
        try:
            api('POST', gh(f'/actions/workflows/{EXECUTE_WORKFLOW}/dispatches'),
                {'ref': 'release', 'inputs': {'reservation_issue': str(number)}})
        except Exception:
            api('DELETE', issue_path(number) + '/labels/' + DISPATCHED)
            raise
        print('Dispatched issue #', number)
        return
    print('No due production reservations')


def claim():
    caller = require('GITHUB_ACTOR')
    if caller.lower() != 'github-actions[bot]':
        operator(caller)
    issue = api('GET', issue_path(require('ISSUE_NUMBER')))
    d = issue_data(issue)
    if not d or issue.get('state') != 'open' or DISPATCHED not in labels(issue):
        raise ValueError('Issue is not a valid open, dispatched, signed reservation')
    if d['_due'] > dt.datetime.now(JST):
        raise ValueError('Reservation time has not arrived')
    target_world(d['production_world_id'])
    v = verify_release(d['release_sha'])
    if v['pr_number'] != d['pr_number'] or v['test_sha'] != d['test_sha']:
        raise ValueError('Approved release PR or test SHA changed')
    # Close first, atomically excluding duplicate queued workflow runs.
    api('PATCH', issue_path(issue['number']), {'state': 'closed', 'state_reason': 'completed'})
    api('POST', issue_path(issue['number']) + '/comments', {'body': 'Reservation claimed by workflow run ' + require('GITHUB_RUN_ID') + '. No automatic retries.'})
    print_output('release_sha', d['release_sha'])
    print_output('world_id', d['production_world_id'])
    print_output('test_sha', d['test_sha'])
    print('Claimed issue #', issue['number'], 'world', d['production_world_id'], 'sha', d['release_sha'])



def preupload():
    # Final authorization check AFTER the production Environment has been approved.
    issue = api('GET', issue_path(require('ISSUE_NUMBER')))
    d = issue_data(issue)
    if not d or issue.get('state') != 'closed' or DISPATCHED not in labels(issue):
        raise ValueError('Claimed reservation is missing, altered or was not dispatched')
    if commit(require('RELEASE_SHA')) != d['release_sha']:
        raise ValueError('Release commit changed after reservation')
    if target_world(require('WORLD_ID')) != d['production_world_id']:
        raise ValueError('Production World ID changed after reservation')
    if d['_due'] > dt.datetime.now(JST):
        raise ValueError('Upload is scheduled for a later time')
    valid = verify_release(d['release_sha'])
    if valid['pr_number'] != d['pr_number'] or valid['test_sha'] != d['test_sha']:
        raise ValueError('PR approval or tested SHA changed since reservation')
    print('Final production authorization verified for issue #', issue['number'])


def complete():
    # Called after job ends; reservation has already been claimed and closed.
    api('POST', issue_path(require('ISSUE_NUMBER')) + '/comments', {
        'body': 'Deployment **' + require('JOB_STATUS') + '**. ' + require('RUN_URL')})


def main():
    commands = {'pr-gate': pr_gate, 'reserve': reserve, 'poll': poll,
                'claim': claim, 'preupload': preupload, 'complete': complete}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise ValueError('Expected command: ' + ', '.join(commands))
    commands[sys.argv[1]]()


if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        print('::error::' + str(err), file=sys.stderr)
        sys.exit(1)
