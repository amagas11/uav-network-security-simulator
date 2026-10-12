from collections import Counter
import pytest
from swarm_sim.runtime import PlatformRuntime
from tests.acceptance.test_v19_onpath import configuration


def copied_configuration(duration=3.2,count=10,end=2.4):
    c=configuration(duration,count,end)
    c.attack_specs[0]['parameters']['injection_mode']='CAPTURE_MODIFY_INJECT'
    return c


@pytest.mark.parametrize('duration,count,end',[(3.2,10,2.4),(5,19,3.8),(10,44,7.4),(20,94,15),(30,144,22.4)])
def test_original_transmitted_and_accepted_with_additional_real_tampered_copies(duration,count,end):
    r=PlatformRuntime(copied_configuration(duration,count,end));r.run_to_completion()
    a=r.packet_accounting.snapshot(r.run_id);c=a['causal_evidence'];b=a['business'];counts=a['attacks'][0]['counts']
    original={g['message_id']:g for g in c['generations']}
    assert len(original)==count==b['generated_business_count']==b['origin_business_sent_count']
    assert b['unmodified_business_sent_count']==b['target_business_received_count']==count
    assert not c['interceptions']
    assert len(c['mutations'])==len(c['derivations'])==counts['generated_attack_count']==counts['sent_attack_count']==counts['executed_drop_count']
    if duration==3.2:assert counts['sent_attack_count']==9
    assert len({d['original']['message_id'] for d in c['derivations']})==len(c['derivations'])
    assert len({d['copy']['message_id'] for d in c['derivations']})==len(c['derivations'])
    assert set(d['copy']['message_id'] for d in c['derivations']).isdisjoint(original)
    for mid in original:
        tx=[t for t in c['transmissions'] if t['message_id']==mid and t['receiver_id']==1]
        assert len(tx)==1 and tx[0]['actual_sender_id']==2 and tx[0]['decoded']
        assert any(o['message_id']==mid and o['observer_node_id']==1 and o['security_state']['application_hmac_result']=='PASS' and o['security_state']['replay_check_result']=='PASS' for o in c['security_observations'])
    for d in c['derivations']:
        mid=d['copy']['message_id'];oid=d['original']['message_id']
        assert oid in original and d['capture_time_s']<d['modified_time_s']
        sign=next(s for s in c['signatures'] if s['message_id']==oid)
        assert sign['signed_time_s']<=d['capture_time_s']
        for key in ['claimed_src_id','sequence_no','packet_type','created_time_s','session_id','key_epoch','hmac_digest']:
            assert d['original'][key]==d['copy'][key]
        assert d['modified_fields']==['altitude_m']
        assert d['original']['payload_digest']!=d['copy']['payload_digest']
        assert d['original']['hmac_digest']==sign['hmac_digest']
        tx=next(t for t in c['transmissions'] if t['message_id']==mid)
        assert tx['actual_sender_id']==-1 and tx['receiver_id']==1 and tx['decoded']
        assert d['modified_time_s']==tx['sent_time_s']
        m=next(m for m in c['mutations'] if m['message_id']==mid)
        assert m['original_message_id']==oid and m['original_payload']==sign['payload'] and not m['hmac_recomputed']
        assert any(o['message_id']==mid and o['observer_node_id']==1 and o['security_state']['application_hmac_failure_reason']=='HMAC_MISMATCH' for o in c['security_observations'])
        assert any(o['message_id']==mid and o['result']['executed'] is True and o['result']['request']['action']=='DROP_PACKET' for o in c['actions'])
    assert len({m['original_payload']['altitude_m'] for m in c['mutations']})>1
    assert len({m['payload']['altitude_m'] for m in c['mutations']})>1
    target=Counter(t['message_id'] for t in c['transmissions'] if t['receiver_id']==1 and t['packet_type']=='TELEMETRY')
    assert set(target.values())=={1} and len(target)==count+counts['sent_attack_count']
    latest_original=max(original.values(),key=lambda g:g['created_time_s'])
    assert r.nodes[1].telemetry_by_source[2]==latest_original['payload']


def test_no_source_cannot_create_fdi_copy():
    c=copied_configuration();c.traffic_specs=[]
    r=PlatformRuntime(c);r.run_to_completion()
    a=r.packet_accounting.snapshot(r.run_id)
    assert not a['causal_evidence']['derivations'] and a['attacks'][0]['counts']['sent_attack_count']==0
