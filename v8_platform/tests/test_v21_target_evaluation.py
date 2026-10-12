from swarm_sim.dos_target_evaluation import evaluate_dos_targets


def alarm(node, time, identity):
    return {"event_type": "MODEL_RESULT", "observer_node_id": node, "sim_time_s": time,
            "event_id": identity, "extensions": {"model_result": {"predicted_label": "DOS", "result_id": identity}}}


def arrival(node, time):
    return {"event_type": "RX_SUCCESS", "observer_node_id": node, "sim_time_s": time, "event_id": f"rx-{node}-{time}"}


LABEL = {"attack_family": "DOS", "attack_id": "attack", "target_node_ids": [1], "impact_start_s": .4, "end_s": 2.0}


def test_target_does_not_relabel_gcs_secondary_alarm_as_target_false_positive():
    result = evaluate_dos_targets([alarm(1, .4, "leader"), alarm(0, .6, "gcs"), arrival(1, 2.2)], [LABEL], 3.2)
    assert (result["TP"], result["FP"], result["FN"], result["TN"]) == (1, 0, 0, 0)
    assert result["pfa_fpr"] is None
    assert result["target_alarm_count"] == result["non_target_alarm_count"] == 1
    assert len(result["decisions"]) == 2
    assert result["normal_window_count"] == 0


def test_long_target_normal_windows_are_regenerated_from_actual_arrivals():
    result = evaluate_dos_targets([alarm(1, .4, "leader"), arrival(1, 4.2), arrival(1, 5.2), alarm(1, 5.3, "normal")], [LABEL], 6)
    assert (result["TP"], result["FP"], result["FN"], result["TN"]) == (1, 1, 0, 1)
    assert result["pfa_fpr"] == .5
    assert [row["start_s"] for row in result["normal_windows"]] == [4., 5.]
    assert all(row["arrival_event_ids"] for row in result["normal_windows"])


def test_unobserved_and_partial_windows_do_not_become_true_negatives():
    result = evaluate_dos_targets([alarm(1, .4, "leader")], [LABEL], 6.5)
    assert result["TN"] == 0 and result["pfa_fpr"] is None
    assert {row["reason"] for row in result["excluded_windows"]} >= {"INCOMPLETE_NORMAL_WINDOW", "NO_DECODED_ARRIVAL_OBSERVATION"}


def test_disabled_detector_and_missing_target_are_not_zero_error_performance():
    for result in [evaluate_dos_targets([], [LABEL], 5, enabled=False), evaluate_dos_targets([], [], 5)]:
        assert result["applicable"] is False
        assert result["TP"] is None and result["pfa_fpr"] is None and result["recall_pd"] is None


def test_scope_helpers_never_mutate_original_events_or_labels():
    import copy
    events = [alarm(1, .4, "leader"), alarm(0, .6, "gcs")]
    labels = [LABEL]
    before = copy.deepcopy((events, labels))
    evaluate_dos_targets(events, labels, 3.2)
    assert (events, labels) == before


def test_target_missed_episode_is_a_real_false_negative():
    result = evaluate_dos_targets([alarm(0, .5, "gcs")], [LABEL], 3.2)
    assert result["TP"] == 0 and result["FN"] == 1 and result["recall_pd"] == 0


def test_target_normal_alarm_is_not_dropped_without_decoded_observation():
    result = evaluate_dos_targets([alarm(1, .4, "leader"), alarm(1, 4.4, "normal"), arrival(1, 4.4)], [LABEL], 5)
    assert result["FP"] == 1 and result["TN"] == 0 and result["pfa_fpr"] == 1
