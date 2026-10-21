import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'vrchat_ci.py'
spec = importlib.util.spec_from_file_location('vrchat_ci', SCRIPT)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
ID_TEST = 'wrld_11111111-1111-1111-1111-111111111111'
ID_PROD = 'wrld_22222222-2222-2222-2222-222222222222'
TEST_SHA = 'a' * 40
RELEASE_SHA = 'b' * 40

class Case(unittest.TestCase):
    def setUp(self):
        self.settings = mock.patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'org/repo',
            'GITHUB_REF': 'refs/heads/release',
            'GITHUB_ACTOR': 'maintainer',
            'GITHUB_SHA': RELEASE_SHA,
            'GITHUB_RUN_ID': '12345',
            'VRC_DEPLOY_OPERATORS': 'maintainer,admin',
            'VRC_PROD_ALLOWED_IDS': ID_PROD,
            'VRC_TEST_ALLOWED_IDS': ID_TEST,
            'VRC_QUEUE_SIGNING_KEY': 'f' * 64,
            'PRODUCTION_WORLD_ID': ID_PROD,
            'SCHEDULED_AT_JST': 'NOW',
            'GH_TOKEN': 'mock-token'
        })
        self.settings.start()
        self.addCleanup(self.settings.stop)

    def test_world_id(self):
        self.assertEqual(ID_PROD, v.world(ID_PROD))
        with self.assertRaises(ValueError):
            v.world('wrld_invalid')

    def test_allowlist(self):
        self.assertEqual(ID_PROD, v.target_world(ID_PROD))
        with self.assertRaises(ValueError):
            v.target_world(ID_TEST)

    def test_operator(self):
        v.operator('MAINTAINER')
        with self.assertRaises(ValueError):
            v.operator('outsider')

    def test_schedule_timezone(self):
        instant = v.schedule('2026-11-01T21:00', dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc))
        self.assertEqual(9 * 3600, instant.utcoffset().total_seconds())
        self.assertEqual(21, instant.hour)

    def test_schedule_past(self):
        with self.assertRaises(ValueError):
            v.schedule('2026-01-01T12:00', dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc))

    def test_schedule_future(self):
        with self.assertRaises(ValueError):
            v.schedule('2028-01-01T12:00', dt.datetime(2026, 10, 21, tzinfo=dt.timezone.utc))

    def test_hmac(self):
        data = {'schema': 4, 'repository': 'org/repo', 'release_sha': RELEASE_SHA,
                'production_world_id': ID_PROD,
                'scheduled_at_jst': '2026-11-01T21:00+09:00'}
        issue = {'user': {'login': 'github-actions[bot]'},
                 'body': v.ISSUE_PREFIX + json.dumps({**data, 'signature': v.digest(data)})}
        self.assertEqual(RELEASE_SHA, v.issue_data(issue)['release_sha'])
        changed = json.loads(issue['body'][len(v.ISSUE_PREFIX):])
        changed['production_world_id'] = ID_TEST
        issue['body'] = v.ISSUE_PREFIX + json.dumps(changed)
        self.assertIsNone(v.issue_data(issue))

    def test_issue_author_check(self):
        data = {'schema': 4, 'repository': 'org/repo', 'release_sha': RELEASE_SHA,
                'production_world_id': ID_PROD, 'scheduled_at_jst': '2026-11-01T21:00+09:00'}
        issue = {'user': {'login': 'other'},
                 'body': v.ISSUE_PREFIX + json.dumps({**data, 'signature': v.digest(data)})}
        self.assertIsNone(v.issue_data(issue))

    def test_pr_gate_passes(self):
        with mock.patch.dict(os.environ, {'PR_HEAD_SHA': TEST_SHA,
                                          'PR_HEAD_REF': 'develop',
                                          'PR_HEAD_REPO': 'org/repo'}), \
             mock.patch.object(v, 'test_deployed', return_value=True):
            v.pr_gate()

    def test_pr_gate_requires_actual_deploy(self):
        with mock.patch.dict(os.environ, {'PR_HEAD_SHA': TEST_SHA,
                                          'PR_HEAD_REF': 'develop',
                                          'PR_HEAD_REPO': 'org/repo'}), \
             mock.patch.object(v, 'test_deployed', return_value=False):
            with self.assertRaises(ValueError):
                v.pr_gate()

    def test_review_rejected_without_approval(self):
        pr = {'number': 3, 'user': {'login': 'author'}, 'head': {'sha': TEST_SHA}}
        with mock.patch.object(v, 'get_pages', return_value=[
            {'user': {'login': 'author'}, 'state': 'APPROVED', 'commit_id': TEST_SHA},
            {'user': {'login': 'reviewer'}, 'state': 'CHANGES_REQUESTED', 'commit_id': TEST_SHA}]):
            with self.assertRaises(ValueError):
                v.approved(pr)

    def test_review_approved(self):
        pr = {'number': 3, 'user': {'login': 'author'}, 'head': {'sha': TEST_SHA}}
        with mock.patch.object(v, 'get_pages', return_value=[
            {'user': {'login': 'reviewer'}, 'state': 'APPROVED', 'commit_id': TEST_SHA}]):
            v.approved(pr)

    def test_comments_do_not_revoke_approval(self):
        pr = {'number': 3, 'user': {'login': 'author'}, 'head': {'sha': TEST_SHA}}
        with mock.patch.object(v, 'get_pages', return_value=[
            {'user': {'login': 'reviewer'}, 'state': 'APPROVED', 'commit_id': TEST_SHA},
            {'user': {'login': 'reviewer'}, 'state': 'COMMENTED', 'commit_id': TEST_SHA}]):
            v.approved(pr)

    def test_stale_approval_rejected(self):
        pr = {'number': 3, 'user': {'login': 'author'}, 'head': {'sha': TEST_SHA}}
        with mock.patch.object(v, 'get_pages', return_value=[
            {'user': {'login': 'reviewer'}, 'state': 'APPROVED', 'commit_id': RELEASE_SHA}]):
            with self.assertRaises(ValueError):
                v.approved(pr)

    def test_sources_must_match(self):
        with mock.patch.object(v, 'source_trees', side_effect=[('a','b','c'),('a','b','c')]):
            v.require_same_world_source(TEST_SHA, RELEASE_SHA)
        with mock.patch.object(v, 'source_trees', side_effect=[('a','b','c'),('a','z','c')]):
            with self.assertRaises(ValueError):
                v.require_same_world_source(TEST_SHA, RELEASE_SHA)

    def test_reject_non_release_reservation(self):
        with mock.patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/develop'}):
            with self.assertRaises(ValueError):
                v.reserve()

    def test_claim_rejects_unapproved_actor(self):
        with mock.patch.dict(os.environ, {'GITHUB_ACTOR': 'outsider', 'ISSUE_NUMBER': '5'}):
            with self.assertRaisesRegex(ValueError, 'authorized production operator'):
                v.claim()

    def test_claim_bot_not_rejected_as_operator(self):
        with mock.patch.dict(os.environ, {'GITHUB_ACTOR': 'github-actions[bot]', 'ISSUE_NUMBER': '5'}), \
             mock.patch.object(v, 'api', return_value={'state':'closed'}):
            with self.assertRaisesRegex(ValueError, 'valid open'):
                v.claim()

    def test_reserve_signed_issue_and_sha(self):
        calls=[]
        def fake_api(method,path,data=None):
            calls.append((method,path,data))
            if method=='POST' and path.endswith('/issues'):
                return {'number': 8, 'html_url': 'https://github.com/org/repo/issues/8'}
            return {}
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(Path(d)/'out')}), \
             mock.patch.object(v,'verify_release',return_value={'pr_number':3,'test_sha':TEST_SHA}), \
             mock.patch.object(v,'ensure_label'), mock.patch.object(v,'issues',return_value=[]), \
             mock.patch.object(v,'api',side_effect=fake_api):
            v.reserve()
            self.assertIn('reservation_issue=8', (Path(d)/'out').read_text())
        payload = next(c[2] for c in calls if c[0]=='POST' and c[1].endswith('/issues'))
        self.assertIn('"signature"', payload['body'])

if __name__ == '__main__':
    unittest.main()
