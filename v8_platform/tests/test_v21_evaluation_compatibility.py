from swarm_sim.evaluation import ExperimentEvaluator
LABEL = {'attack_family': 'DOS', 'attack_id': 'attack', 'target_node_ids': [1], 'impact_start_s': .4, 'end_s': 2.0}


def alarm(node, time, identity):
    return {'event_type': 'MODEL_RESULT', 'observer_node_id': node, 'sim_time_s': time,
            'event_id': identity, 'extensions': {'model_result': {'predicted_label': 'DOS', 'result_id': identity}}}


def test_additive_target_evaluation_does_not_overwrite_network_denominator():
    result = ExperimentEvaluator().evaluate(
        [alarm(1, .4, 'target'), alarm(0, .6, 'gcs')], [LABEL],
        run_record={'duration_s': 3.2, 'run_config': {'flooding_detection_enabled': True}},
    )
    network = result['per_attack_family']['DOS']
    assert (network['TP'], network['FP'], network['FN'], network['TN']) == (1, 1, 0, 2)
    assert network['pfa_fpr'] == 1 / 3
    assert result['dos_target_receiver_evaluation']['pfa_fpr'] is None
    assert len(result['dos_target_receiver_evaluation']['decisions']) == 2


def test_disabled_scope_extends_metadata_without_inventing_performance():
    result = ExperimentEvaluator().evaluate([], [LABEL], run_record={
        'duration_s': 3.2, 'run_config': {'flooding_detection_enabled': False},
    })
    assert result['detector_applicability']['DOS']['applicable'] is False
    assert result['dos_target_receiver_evaluation']['recall_pd'] is None
