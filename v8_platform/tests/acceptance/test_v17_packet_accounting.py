from copy import deepcopy
import math
import pytest
from swarm_sim.runtime import PlatformRuntime
from swarm_sim.packet_accounting import PacketAccounting
from swarm_sim.simulation import RunConfig
from swarm_sim.demo_budget import validate_demo_budget


def make(family='DOS', rate=80, duration=3.2, count=8):
    plan=dict(attack_family=family, attack_subtype={'DOS':'FLOODING','FDI':'TELEMETRY_ABRUPT_CHANGE','SPOOFING':'KNOWN_ID_CONFLICT','REPLAY':'IMMEDIATE_REPLAY'}[family],scheduled_start_s=0,impact_start_s=.4,end_s=2 if family=='DOS' else 2.4,attacker_node_id=2 if family=='FDI' else -1,target_node_ids=[1],target_link_ids=[],intensity={'value':rate,'unit':'pps'} if family=='DOS' else {},parameters={'field':'altitude_m','absolute_offset':.1} if family=='FDI' else {'claimed_src_id':0} if family=='SPOOFING' else {})
    return RunConfig(duration_s=duration,step_s=.2,auto_traffic=False,queue_capacity=128,tx_service_per_step=64,rx_service_per_step=64,flooding_packet_rate_threshold_pps=8 if family=='DOS' else 12,attack_specs=[plan],traffic_specs=[dict(source_node_id=2,target_node_id=1,packet_type='TELEMETRY',payload={'altitude_m':100},start_s=.2,interval_s=.2 if family=='FDI' else .4,count=count)])


@pytest.mark.parametrize('rate,expected',[(80,128),(500,800),(9,14)])
def test_flood_quota_real_execution(rate,expected):
    runtime=PlatformRuntime(make(rate=rate,count=6))
    runtime.start();runtime.run_to_completion()
    view=runtime.runtime_view()['packet_accounting'];c=view['attacks'][0]['counts']
    assert c['planned_attack_count']==expected
    assert c['generated_attack_count']==c['sent_attack_count']==expected
    assert c['target_received_count']<=expected
    assert c['executed_drop_count']<=c['hmac_failure_count']<=c['target_received_count']
    assert view==runtime.runtime_view()['packet_accounting']


def test_fdi_partition_no_extra_business_generation():
    runtime=PlatformRuntime(make('FDI',count=10));runtime.start();runtime.run_to_completion()
    v=runtime.runtime_view()['packet_accounting'];b=v['business'];a=v['attacks'][0]['counts']
    assert b['generated_business_count']==10
    assert a['eligible_count']==a['modified_count']==a['sent_attack_count']==9
    assert b['unmodified_business_sent_count']==1
    assert b['origin_business_sent_count']==b['unmodified_business_sent_count']+a['sent_attack_count']==10


def test_spoof_default_actual_chain():
    runtime=PlatformRuntime(make('SPOOFING',count=6));runtime.start();runtime.run_to_completion()
    v=runtime.runtime_view()['packet_accounting'];a=v['attacks'][0]['counts']
    assert v['business']['generated_business_count']==6
    assert a['attempt_count']==a['generated_attack_count']==a['sent_attack_count']==10
    assert a['detected_report_count']==a['executed_drop_count']==10


def test_pause_reset_and_run_isolation():
    runtime=PlatformRuntime(make());runtime.start();runtime.step();runtime.pause()
    before=runtime.runtime_view()['packet_accounting'];runtime.step()
    assert before==runtime.runtime_view()['packet_accounting']
    runtime.resume();runtime.run_to_completion();runtime.reset()
    v=runtime.runtime_view()['packet_accounting']
    assert v['business']['generated_business_count']==0
    assert v['attacks'][0]['counts']['sent_attack_count']==0


def test_accounting_dedup_and_failed_action():
    config=make('FDI');counter=PacketAccounting(config)
    from swarm_sim.attacks import AttackPlan
    plan=AttackPlan(**deepcopy(config.attack_specs[0]));plan.attack_id='a';counter.register_attack(plan)
    c=counter.attack('a');counter.add(c,'sent_attack_count','same');counter.add(c,'sent_attack_count','same')
    assert c['sent_attack_count']==1
    from types import SimpleNamespace
    frame=SimpleNamespace(runtime_attack_id='a')
    result={'request':{'request_id':'r','action':'DROP_PACKET'},'executed':False}
    counter.detection(1,frame,'AUTH_FAILURE',result);counter.detection(1,frame,'AUTH_FAILURE',result)
    assert c['detected_report_count']==1 and c['executed_drop_count']==0


def test_demo_budget_rejects_not_silently_clamps():
    data=dict(demo_profile='V17',duration_s=30,step_s=.2,traffic_specs=[],attack_specs=[dict(attack_family='DOS',impact_start_s=.4,end_s=20.4,intensity={'value':500})])
    with pytest.raises(ValueError,match='5000'):validate_demo_budget(data)
    data['attack_specs'][0]['end_s']=2
    validate_demo_budget(data)


def test_replay_waiting_checks_are_not_retransmission_attempts():
    config=make('REPLAY',count=1)
    config.attack_specs[0]['attack_subtype']='DELAYED_REPLAY'
    config.attack_specs[0]['parameters']={'delay_s':.8}
    runtime=PlatformRuntime(config);runtime.start();runtime.run_to_completion()
    counts=runtime.runtime_view()['packet_accounting']['attacks'][0]['counts']
    assert counts['candidate_check_count']>1
    assert counts['attempt_count']==counts['sent_attack_count']==1
