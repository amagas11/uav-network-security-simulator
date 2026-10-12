"""Scientific denominators and pre-HMAC cross-category load, not UI target values."""
from collections import deque
import pytest
from swarm_sim.runtime import PlatformRuntime
from swarm_sim.evaluation import ExperimentEvaluator
from tests.acceptance.test_v20_fdi_copies import copied_configuration


@pytest.mark.parametrize('duration,count,end', [(3.2,10,2.4),(5,19,3.8),(10,44,7.4),(20,94,15),(30,144,22.4)])
def test_fdi_every_decoded_arrival_once_and_real_cross_threshold(duration,count,end):
    config=copied_configuration(duration,count,end)
    config.flooding_packet_rate_threshold_pps=12
    runtime=PlatformRuntime(config);runtime.run_to_completion()
    windows={};seen=set();cross=[]
    for event in runtime.events:
        if event['event_type']!='RX_SUCCESS':continue
        assert event['event_id'] not in seen;seen.add(event['event_id'])
        q=windows.setdefault(event['observer_node_id'],deque())
        time=event['sim_time_s'];q.append(time)
        while q and q[0]<time-1:q.popleft()
        traffic=event['online_features']['traffic']
        assert traffic['total_packet_count']==len(q)
        # Generic traffic enrichment includes RX_FAILURE and a 1e-12 boundary
        # tolerance. Do not substitute its rate for the detector's exact deque.
        if event['observer_node_id']==1 and len(q)>=12:cross.append(event)
    assert cross, 'original + extra copies can truly exceed the existing threshold'
    causal=runtime.packet_accounting.snapshot(runtime.run_id)['causal_evidence']
    target=[t for t in causal['transmissions'] if t['decoded'] and t['receiver_id']==1]
    assert all(t['packet_type']=='TELEMETRY' for t in target), 'no report feedback path to target'
    assert len({t['emission_id'] for t in target})==len(target)
    assert len(target)==count+len(causal['derivations'])
    assert all(a['result']['executed'] for a in causal['actions'] if a['result']['request']['action']=='DROP_PACKET')


def test_eaves_reception_fraction_is_event_not_generated_message_fraction():
    def event(kind,at,mid,node):
        return dict(event_type=kind,sim_time_s=at,message_id=mid,observer_node_id=node,
                    online_features={'traffic':{}})
    events=[event('RX_SUCCESS',.2,'control',1),event('RX_SUCCESS',.4,'business',1),
            event('RX_SUCCESS',.4,'business',0),event('RX_FAILURE',1.,'other',3),
            event('TX_FAILURE',.3,'key-not-ready',2),event('RX_SUCCESS',1.2,'outside',1)]
    points=ExperimentEvaluator._traffic_points(events,.2,1.)
    assert len(points)==4 # inclusive endpoints, repeated message at another hop is another event.
    assert sum(not point['failure'] for point in points)==3
    assert sum(not point['failure'] for point in points)/len(points)==.75
    assert len(ExperimentEvaluator._traffic_points(events,2,3))==0
