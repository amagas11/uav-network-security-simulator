import pytest
from types import SimpleNamespace
from swarm_sim.runtime import PlatformRuntime
from swarm_sim.simulation import RunConfig
from swarm_sim.receiver_observations import ReceiverRateObservations
from swarm_sim.telemetry_measurement import measured_payload, validate_measurement_model


@pytest.mark.parametrize('duration,count,end', [(3.2,10,2.4),(5,19,3.8),(10,44,7.4),(20,94,15),(30,144,22.4)])
def test_real_measurement_signature_mutation_transmission(duration, count, end):
    model = dict(name='BOUNDED_ALTITUDE_SENSOR', amplitude_m=.04, period_s=2)
    config = RunConfig(duration_s=duration, step_s=.2, auto_traffic=False,
        queue_capacity=128, tx_service_per_step=64, rx_service_per_step=64,
        flooding_packet_rate_threshold_pps=500,
        traffic_specs=[dict(source_node_id=2,target_node_id=1,packet_type='TELEMETRY',
            payload={},measurement_model=model,start_s=.2,interval_s=.2,count=count,
            session_id='source',sequence_start=100)],
        attack_specs=[dict(attack_family='FDI',attack_subtype='TELEMETRY_ABRUPT_CHANGE',
            scheduled_start_s=0,impact_start_s=.4,end_s=end,attacker_node_id=2,target_node_ids=[1],
            parameters=dict(field='altitude_m',absolute_offset=.1,bias_model='BOUNDED_PERIODIC',
                            bias_amplitude_m=.04,bias_period_packets=11))])
    runtime = PlatformRuntime(config)
    runtime.run_to_completion()
    data = runtime.packet_accounting.snapshot(runtime.run_id)
    causal=data['causal_evidence']
    generations={r['message_id']:r for r in causal['generations']}
    signatures={r['message_id']:r for r in causal['signatures']}
    tx={r['message_id']:r for r in causal['transmissions'] if r['hop_index']==0}
    assert len(set(r['payload']['altitude_m'] for r in generations.values()))>1
    assert len(set(r['payload']['altitude_m'] for r in causal['mutations']))>1
    assert len({r['message_id'] for r in causal['mutations']})==len(causal['mutations'])
    if duration==3.2:
        assert len(generations)==10 and len(causal['mutations'])==9
    for mutation in causal['mutations']:
        key=mutation['message_id']
        assert key in generations and key in tx
        assert signatures[key]['payload']==mutation['original_payload']
        assert signatures[key]['hmac_digest']==mutation['hmac_digest']
        assert signatures[key]['signed_time_s']<=mutation['modified_time_s']<=tx[key]['sent_time_s']
        assert .05999<=mutation['payload']['altitude_m']-mutation['original_payload']['altitude_m']<=.14001
        assert mutation['hmac_recomputed'] is False
        assert any(r['message_id']==key and r['security_state']['application_hmac_failure_reason']=='HMAC_MISMATCH' for r in causal['security_observations'])
        assert any(r['message_id']==key and r['result']['executed'] for r in causal['actions'])
    first=min(generations.values(),key=lambda r:r['created_time_s'])['message_id']
    assert any(r['message_id']==first and r['security_state']['application_hmac_result']=='PASS' for r in causal['security_observations'])


def test_sensor_is_bounded_deterministic_and_not_a_flight_trajectory():
    node=SimpleNamespace(position_xyz_m=(0,0,100),flight_state='DISARMED')
    model=dict(name='BOUNDED_ALTITUDE_SENSOR',amplitude_m=.04,period_s=2)
    validate_measurement_model(model,'TELEMETRY')
    result=measured_payload({},model,node,.2,23)
    assert result==measured_payload({},model,node,.2,23)
    assert abs(result['altitude_m']-100)<=.04 and result['flight_state']=='DISARMED'
    with pytest.raises(ValueError):
        validate_measurement_model(dict(model,amplitude_m=100),'TELEMETRY')


def test_receiver_observation_is_bounded_readonly_and_keeps_boundary():
    observer=ReceiverRateObservations([1],1,8,capacity=3)
    statistics={'packet_rate_pps':1.0}
    observer.arrival(1,0,statistics)
    observer.arrival(0,0,statistics)
    observer.sample(1)
    assert observer.snapshot()['nodes'][0]['samples'][0]['packet_rate_pps']==1
    observer.sample(1.2)
    assert observer.snapshot()['nodes'][0]['samples'][-1]['packet_rate_pps']==0
    for time in (2,3,4): observer.sample(time)
    snap=observer.snapshot()
    assert len(snap['nodes'][0]['samples'])==3 and snap['capacity_per_node']==3
    assert statistics=={'packet_rate_pps':1.0}


def test_four_capture_classes_are_exclusive_and_control_plaintext_is_a_subset():
    from collections import Counter
    from swarm_sim.packet_accounting import PacketAccounting
    accounting=PacketAccounting(RunConfig(duration_s=1))
    record=SimpleNamespace(plan=SimpleNamespace(attack_id='eve'))
    accounting.attacks['eve']={'counts':Counter()}
    for index,(sensitive,encrypted) in enumerate([(True,True),(True,False),(False,True),(False,False)]):
        accounting.eaves_captured(record,SimpleNamespace(message_id=str(index),hop_index=0,
            sensitive=sensitive,encrypted=encrypted,packet_type='SKG_CONTROL' if not sensitive and not encrypted else 'DATA'))
    counts=accounting.attack('eve')
    keys=['captured_sensitive_ciphertext_count','captured_sensitive_plaintext_count','captured_nonsensitive_ciphertext_count','captured_nonsensitive_plaintext_count']
    assert sum(counts[key] for key in keys)==counts['captured_frame_count']==4
    assert all(counts[key]==1 for key in keys)
    assert counts['captured_protocol_control_plaintext_count']==1


@pytest.mark.parametrize('rate',[80,200,500])
def test_dos_observation_does_not_change_detection_or_network(rate):
    config=RunConfig(duration_s=3.2,step_s=.2,auto_traffic=False,queue_capacity=128,
        tx_service_per_step=64,rx_service_per_step=64,flooding_packet_rate_threshold_pps=8,
        traffic_specs=[dict(source_node_id=2,target_node_id=1,packet_type='STATUS',payload={'status_code':1},
            start_s=.2,interval_s=.3,count=8)],
        attack_specs=[dict(attack_family='DOS',attack_subtype='FLOODING',scheduled_start_s=0,
            impact_start_s=.4,end_s=2,attacker_node_id=-1,target_node_ids=[1],
            intensity=dict(unit='pps',value=rate),parameters={})])
    observed=PlatformRuntime(config);observed.run_to_completion()
    disabled=PlatformRuntime(config)
    disabled.receiver_rate_observations=ReceiverRateObservations([],1,8)
    disabled.run_to_completion()
    assert observed.packet_accounting.snapshot(observed.run_id)['attacks'][0]['counts']==disabled.packet_accounting.snapshot(disabled.run_id)['attacks'][0]['counts']
    def event_digest(runtime):
            return [(e['event_type'],e['observer_node_id'],e['sim_time_s'],e['online_features'].get('security_state'),e['online_features'].get('traffic')) for e in runtime.events]
    assert event_digest(observed)==event_digest(disabled)
    actual=[e['online_features']['traffic']['packet_rate_pps'] for e in observed.events if e['observer_node_id']==1 and e['event_type']=='RX_SUCCESS']
    snapshot=observed.runtime_view()['receiver_rate_observations']['nodes'][0]
    assert snapshot['peak_window_rate_pps']==max(actual)
    assert len(snapshot['samples'])<=320
