import pytest
from swarm_sim.runtime import PlatformRuntime
from swarm_sim.simulation import RunConfig
from app.app import build_application_runtime_factory

@pytest.mark.parametrize('duration,count',[(4,18),(5,23),(10,48),(20,98),(30,148)])
def test_eaves_business_and_frame_sets_are_distinct(duration,count):
    r=build_application_runtime_factory().create(RunConfig(seed=31,duration_s=duration,step_s=.1,auto_traffic=False,encrypt_sensitive=True,queue_capacity=128,
      tx_service_per_step=32,rx_service_per_step=32,phy_sample_interval_s=10,flooding_packet_rate_threshold_pps=12,
      traffic_specs=[dict(source_node_id=2,target_node_id=1,packet_type='STATUS',payload=dict(status_code=1,value=42),
        start_s=.1,interval_s=.2,count=count,sensitive=True,encrypt=True,session_id='official-web-eaves-session',sequence_start=100)],
      attack_specs=[dict(attack_family='EAVESDROPPING',attack_subtype='CIPHERTEXT_ONLY',scheduled_start_s=0,impact_start_s=.1,end_s=duration-.2,
        attacker_node_id=-1,target_node_ids=[1],target_link_ids=['link-2-1'],intensity={},parameters=dict(receiver_radius_m=1000))]))
    r.run_to_completion()
    a=r.packet_accounting.snapshot(r.run_id);c=a['causal_evidence'];counts=a['attacks'][0]['counts']
    generated={g['message_id'] for g in c['generations']}
    sent={t['message_id'] for t in c['transmissions'] if t['hop_index']==0 and t['message_id'] in generated}
    captures=[f for f in c['captures'] if f['family']=='EAVESDROPPING']
    cipher={f['message_id'] for f in captures if f['sensitive'] and f['encrypted']}
    control=[f for f in captures if f['packet_type']=='SKG_CONTROL' and not f['sensitive'] and not f['encrypted']]
    assert len(generated)==count and len(sent)==a['business']['origin_business_sent_count']
    assert cipher<=sent and not ({f['message_id'] for f in control}&generated)
    for mid in generated-sent:
        assert any(o.get('extensions',{}).get('crypto_send_failure',{}).get('withheld_message_ref')==mid for o in c['security_observations'])
    assert sum(counts[k] for k in ['captured_sensitive_ciphertext_count','captured_sensitive_plaintext_count','captured_nonsensitive_ciphertext_count','captured_nonsensitive_plaintext_count'])==counts['captured_frame_count']==len(captures)
    if duration==5:
        assert (len(generated),len(sent),len(cipher),len(captures),len(control),counts['plaintext_exposure_count'])==(23,21,19,21,2,0)
        assert len(generated-sent)==2 and len(sent-cipher)==2

@pytest.mark.parametrize('duration,count,end',[(3.2,6,2.4),(5,10,3.8),(10,23,7.4),(20,48,15),(30,73,22.4)])
def test_spoofing_all_derivations_have_unique_real_sources(duration,count,end):
    r=build_application_runtime_factory().create(RunConfig(duration_s=duration,step_s=.2,auto_traffic=False,
      queue_capacity=128,tx_service_per_step=64,rx_service_per_step=64,flooding_packet_rate_threshold_pps=12,
      traffic_specs=[dict(source_node_id=2,target_node_id=1,packet_type='STATUS',payload=dict(status_code=1,value=42),start_s=.2,interval_s=.4,count=count,session_id='source',sequence_start=100)],
      attack_specs=[dict(attack_family='SPOOFING',attack_subtype='KNOWN_ID_CONFLICT',scheduled_start_s=0,impact_start_s=.4,end_s=end,
        attacker_node_id=-1,target_node_ids=[1],parameters=dict(claimed_src_id=0,source_copy_mode='LEGITIMATE_FRAME_COPY',legitimate_source_id=2))]))
    r.run_to_completion();c=r.packet_accounting.snapshot(r.run_id)['causal_evidence']
    ds=c['derivations'];assert len({d['original']['message_id'] for d in ds})==len({d['copy']['message_id'] for d in ds})==len(ds)
    for d in ds:
        original=d['original'];copy=d['copy']
        tx=next(t for t in c['transmissions'] if t['message_id']==copy['message_id'])
        assert d['capture_time_s']<tx['sent_time_s']
        assert original['signed'] and original['claimed_src_id']==2 and copy['claimed_src_id']==0
        assert original['hmac_digest']==copy['hmac_digest'] and original['payload_digest']==copy['payload_digest']
        assert any(t['message_id']==original['message_id'] and t['sent_time_s']<=d['capture_time_s'] for t in c['transmissions'])
        assert any(o['message_id']==copy['message_id'] and o['security_state']['application_hmac_failure_reason']=='HMAC_MISMATCH' for o in c['security_observations'])
