from collections import Counter
import pytest
from swarm_sim.runtime import PlatformRuntime
from swarm_sim.simulation import RunConfig


def configuration(duration=3.2,count=10,end=2.4):
    return RunConfig(duration_s=duration,step_s=.2,auto_traffic=False,queue_capacity=128,
        tx_service_per_step=64,rx_service_per_step=64,flooding_packet_rate_threshold_pps=500,
        traffic_specs=[dict(source_node_id=2,target_node_id=1,packet_type='TELEMETRY',payload={},
            measurement_model=dict(name='BOUNDED_ALTITUDE_SENSOR',amplitude_m=.04,period_s=2),
            start_s=.2,interval_s=.2,count=count,session_id='source',sequence_start=100)],
        attack_specs=[dict(attack_family='FDI',attack_subtype='TELEMETRY_ABRUPT_CHANGE',scheduled_start_s=0,
            impact_start_s=.4,end_s=end,attacker_node_id=-1,target_node_ids=[1],target_link_ids=['link-2-1'],
            parameters=dict(injection_mode='ON_PATH_INTERCEPTION_REPLACEMENT',legitimate_source_id=2,
                field='altitude_m',absolute_offset=.1,bias_model='BOUNDED_PERIODIC',bias_amplitude_m=.04,bias_period_packets=11))])


@pytest.mark.parametrize('duration,count,end',[(3.2,10,2.4),(5,19,3.8),(10,44,7.4),(20,94,15),(30,144,22.4)])
def test_real_external_relay_replaces_original_once(duration,count,end):
    r=PlatformRuntime(configuration(duration,count,end));r.run_to_completion()
    data=r.packet_accounting.snapshot(r.run_id);c=data['causal_evidence'];b=data['business'];a=data['attacks'][0]['counts']
    assert r.nodes[-1].role.value=='EXTERNAL'
    assert b['generated_business_count']==b['origin_business_sent_count']==count
    assert b['target_business_received_count']==count
    assert len(c['interceptions'])==a['modified_count']==a['sent_attack_count']==a['executed_drop_count']
    if duration==3.2:assert a['modified_count']==9
    target=Counter(t['message_id'] for t in c['transmissions'] if t['receiver_id']==1 and t['message_id'] in r.packet_accounting.messages and r.packet_accounting.messages[t['message_id']].get('business'))
    assert set(target.values())=={1}  # no original+replacement duplicate target delivery
    for i in c['interceptions']:
        assert i['source_id']==2 and i['attacker_id']==-1 and i['target_id']==1
        assert i['replacement_queued'] and i['original_target_delivery_suppressed'] and i['target_decoded']
        m=next(m for m in c['mutations'] if m['message_id']==i['message_id'])
        sign=next(s for s in c['signatures'] if s['message_id']==i['message_id'])
        assert sign['signed_time_s']<=i['capture_time_s']<=m['modified_time_s']<i['replacement_sent_time_s']
        assert i['original_frame']['receiver_id']==-1
        assert i['replacement_frame']['sender_id']==-1 and i['replacement_frame']['receiver_id']==1
        assert i['original_emission_id']!=i['replacement_emission_id']
        assert i['replacement_frame']['claimed_src_id']==i['original_frame']['claimed_src_id']==2
        assert i['original_frame']['hmac_digest']==i['replacement_frame']['hmac_digest']==sign['hmac_digest']
        assert m['changed_fields']==['altitude_m'] and not m['hmac_recomputed']
        assert any(o['message_id']==i['message_id'] and o['observer_node_id']==1 and o['security_state']['application_hmac_failure_reason']=='HMAC_MISMATCH' for o in c['security_observations'])
        assert any(o['message_id']==i['message_id'] and o['result']['executed'] and o['result']['request']['action']=='DROP_PACKET' for o in c['actions'])
    first=c['generations'][0]['message_id']
    assert any(o['message_id']==first and o['observer_node_id']==1 and o['security_state']['application_hmac_result']=='PASS' for o in c['security_observations'])


def test_external_model_rejects_unscoped_path_and_key_owner():
    for field,value in [('attacker_node_id',2),('target_link_ids',[])]:
        c=configuration();c.attack_specs[0][field]=value
        with pytest.raises(ValueError):PlatformRuntime(c)

def test_failed_physical_interception_cannot_create_replacement():
    r=PlatformRuntime(configuration());sample=r.phy.sample
    def fail_external(*args,**kwargs):
        outcome=sample(*args,**kwargs)
        if args[2].node_id==-1:outcome.decode_success=False
        return outcome
    r.phy.sample=fail_external;r.run_to_completion()
    c=r.packet_accounting.snapshot(r.run_id)['causal_evidence']
    assert not c['interceptions'] and not c['mutations']
    assert len([t for t in c['transmissions'] if t['receiver_id']==1 and t['packet_type']=='TELEMETRY'])==1
    assert -1 not in r.application_auth._keys
