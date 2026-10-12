import pytest
from swarm_sim.evaluation import EvaluationPolicyRegistry

@pytest.mark.parametrize('score,available,bounded', [(None,False,True),(0,True,True),(.5,True,True),(.50001,True,False),(1,True,False),(True,False,False)])
def test_harm_metadata_preserves_valid_and_legacy_results(score,available,bounded):
    # The legacy formula is retained; explicit availability prevents UI success
    # from being inferred from the legacy default for a missing policy input.
    registry=EvaluationPolicyRegistry()
    result=registry.evaluate(family='DOS',subtype='FLOODING',action_executed=True,
        action='INCREASE_MONITORING',action_time_s=.4,start_s=.4,end_s=2,events=[],
        outcome={'malicious_traffic_blocked':1,'receiver_total_rate_exceeded':True},
        service={},defense_outcome={'legitimate_traffic_harm_score':score},scope=None)
    assert result.evidence['legitimate_harm_available'] is available
    assert result.evidence['legitimate_harm_bounded'] is bounded
    assert result.effective is bounded
