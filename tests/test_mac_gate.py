"""No real GitHub API or VRChat uploads; unit tests for the independent Mac broker."""
import datetime as dt
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

BROKER_PATH = Path(__file__).resolve().parents[1] / 'mac-gate' / 'broker.py'
spec = importlib.util.spec_from_file_location('vrchat_mac_broker', BROKER_PATH)
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

TEST_ID = 'wrld_11111111-1111-1111-1111-111111111111'
PROD_ID = 'wrld_22222222-2222-2222-2222-222222222222'
RELEASE_SHA = 'a'*40
TEST_SHA = 'b'*40


class FakeGithub:
    def __init__(self, runs): self.runs = runs
    def get(self, path): return self.runs[path]


class GateTests(unittest.TestCase):
    def setUp(self):
        self.policy = {'repository':'rin0700/vrcli-testrepositoy','repository_id':12345,
            'allowed_actor_ids':[100,200], 'production_world_ids':[PROD_ID],
            'test_world_ids':[TEST_ID], 'worktree':'/Users/vrchatprod/world-production',
            'remote_url':'git@github.com:rin0700/vrcli-testrepositoy.git',
            'vrcli_account':'Gugenka',
            'oidc_audience':'urn:vrchat:prod:rin0700/vrcli-testrepositoy'}
        self.secrets={'github_read_token':'not-a-real-token','queue_signing_key':'a'*64}
        self.record={'schema':4, 'repository': self.policy['repository'],
           'production_world_id':PROD_ID,'release_sha':RELEASE_SHA,
           'test_sha':TEST_SHA,'pr_number':12,'scheduled_at_jst':'2025-05-01T20:00+09:00',
           'request_run_id':42, 'requested_by':'rin0700'}

    def sign_issue(self, record=None):
        rec=dict(record or self.record)
        raw=json.dumps(rec, sort_keys=True,ensure_ascii=False,separators=(',', ':')).encode()
        rec['signature']=hmac.new(self.secrets['queue_signing_key'].encode(),raw,hashlib.sha256).hexdigest()
        return {'body':broker.ISSUE_PREFIX+json.dumps(rec, ensure_ascii=False),
                'user':{'login':'github-actions[bot]'}, 'state':'closed',
                'labels':[{'name':broker.LABEL},{'name':broker.DISPATCHED}]}

    def fake_run(self, user_id=100, login='rin0700'):
        return FakeGithub({'/actions/runs/42': {
           'id':42,'event':'workflow_dispatch','conclusion':'success',
           'path':'.github/workflows/vrchat-prod-reserve.yml','head_branch':'release',
           'head_sha':RELEASE_SHA,'actor':{'id':user_id,'login':login}}})

    def test_policy_valid(self):
        self.assertTrue(broker.validate_config(self.policy,self.secrets))

    def test_policy_prevents_test_prod_overlap(self):
        self.policy['test_world_ids'].append(PROD_ID)
        with self.assertRaises(PermissionError): broker.validate_config(self.policy,self.secrets)

    def test_good_issue(self):
        self.assertEqual(broker.verified_queue_issue(self.sign_issue(),self.policy,self.secrets),self.record)

    def test_modified_world_rejected(self):
        issue=self.sign_issue()
        issue['body']=issue['body'].replace(PROD_ID,TEST_ID)
        with self.assertRaises(PermissionError): broker.verified_queue_issue(issue,self.policy,self.secrets)

    def test_valid_signature_but_world_unapproved_rejected(self):
        rec=dict(self.record,production_world_id='wrld_33333333-3333-3333-3333-333333333333')
        with self.assertRaises(PermissionError): broker.verified_queue_issue(self.sign_issue(rec),self.policy,self.secrets)

    def test_signature_but_wrong_repository_rejected(self):
        rec=dict(self.record,repository='attacker/fork')
        with self.assertRaises(PermissionError): broker.verified_queue_issue(self.sign_issue(rec),self.policy,self.secrets)

    def test_open_or_unclaimed_reservation_rejected(self):
        issue=self.sign_issue();issue['state']='open'
        with self.assertRaises(PermissionError): broker.verified_queue_issue(issue,self.policy,self.secrets)
        issue=self.sign_issue();issue['labels']=[{'name':broker.LABEL}]
        with self.assertRaises(PermissionError): broker.verified_queue_issue(issue,self.policy,self.secrets)

    def test_future_date_rejected(self):
        rec=dict(self.record,scheduled_at_jst='2099-01-01T20:00+09:00')
        with self.assertRaises(PermissionError): broker.verified_queue_issue(self.sign_issue(rec),self.policy,self.secrets)

    def test_authorized_original_run_actor(self):
        actor=broker.verify_booking_actor(self.fake_run(),self.record,self.policy)
        self.assertEqual(actor['id'],100)

    def test_removed_original_actor_rejected(self):
        with self.assertRaises(PermissionError):broker.verify_booking_actor(self.fake_run(222),self.record,self.policy)

    def test_actor_must_match_signed_request(self):
        with self.assertRaises(PermissionError):broker.verify_booking_actor(self.fake_run(100,'someoneelse'),self.record,self.policy)

    def test_wrong_booking_workflow_rejected(self):
        gh=self.fake_run()
        gh.runs['/actions/runs/42']['path']='.github/workflows/evil.yml'
        with self.assertRaises(PermissionError):broker.verify_booking_actor(gh,self.record,self.policy)

    def test_oidc_enforces_workflow_identity(self):
        claims={'repository_id':'12345','repository':self.policy['repository'],'ref':'refs/heads/release',
                'event_name':'workflow_dispatch','workflow_ref': self.policy['repository']+'/'+broker.EXPECTED_EXECUTE+'@refs/heads/release',
                'environment':'vrchat-production','run_id':'137'}
        class Key: key='not-used-by-mock'
        class FakeJWK:
            def __init__(self,url): pass
            def get_signing_key_from_jwt(self, token): return Key()
        with patch.object(broker.jwt,'PyJWKClient',FakeJWK), patch.object(broker.jwt,'decode',return_value=claims):
            self.assertEqual(broker.verify_oidc('a.b.c',self.policy)['run_id'],'137')
            claims['workflow_ref']='attacker/not-authorized'
            with self.assertRaises(PermissionError): broker.verify_oidc('a.b.c',self.policy)

    def test_execute_run_identity(self):
        gh=FakeGithub({'/actions/runs/123':{'id':123,'path':broker.EXPECTED_EXECUTE,
           'event':'workflow_dispatch','head_branch':'release'}})
        broker.verify_execute_run(gh,{'run_id':'123'})
        gh.runs['/actions/runs/123']['head_branch']='develop'
        with self.assertRaises(PermissionError):broker.verify_execute_run(gh,{'run_id':'123'})


if __name__=='__main__': unittest.main()
