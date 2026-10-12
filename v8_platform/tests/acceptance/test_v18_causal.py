"""Real source/clone causality; no assumed counts substituted for execution."""
import pytest
from swarm_sim.runtime import PlatformRuntime
from swarm_sim.simulation import RunConfig
from app.app import build_application_runtime_factory


def config(duration=3.2, count=None):
    step = .2
    count = count if count is not None else int((duration - 1 - .2 + 1e-9) // .4) + 1
    align = lambda value: round(round(value / step) * step, 9)
    return RunConfig(duration_s=duration, step_s=step, auto_traffic=False,
        queue_capacity=128, tx_service_per_step=64, rx_service_per_step=64,
        flooding_packet_rate_threshold_pps=12,
        traffic_specs=[dict(source_node_id=2, target_node_id=1, packet_type='STATUS',
            payload={'status_code': 1, 'value': 42}, start_s=.2, interval_s=.4, count=count,
            session_id='source', sequence_start=100)],
        attack_specs=[dict(attack_family='SPOOFING', attack_subtype='KNOWN_ID_CONFLICT',
            scheduled_start_s=0, impact_start_s=align(.4 * duration / 3.2),
            end_s=align(2.4 * duration / 3.2), attacker_node_id=-1, target_node_ids=[1],
            parameters={'claimed_src_id': 0, 'source_copy_mode': 'LEGITIMATE_FRAME_COPY',
                        'legitimate_source_id': 2})])


@pytest.mark.parametrize('duration', [3.2, 5, 10, 20, 30])
def test_original_signed_sent_then_one_copy(duration):
    runtime = build_application_runtime_factory().create(config(duration))
    runtime.run_to_completion()
    accounting = runtime.runtime_view()['packet_accounting']
    audit = accounting['causal_evidence']
    rows = audit['derivations']
    assert rows
    assert len({row['original']['message_id'] for row in rows}) == len(rows)
    assert len({row['copy']['message_id'] for row in rows}) == len(rows)
    generated = {row['message_id'] for row in audit['generations']}
    tx = {row['message_id']: row for row in audit['transmissions'] if row['hop_index'] == 0}
    for row in rows:
        original, copy = row['original'], row['copy']
        assert original['message_id'] in generated and original['signed']
        assert original['message_id'] != copy['message_id']
        assert original['claimed_src_id'] == 2 and copy['claimed_src_id'] == 0
        assert tx[original['message_id']]['sent_time_s'] == row['capture_time_s']
        assert row['capture_time_s'] < row['modified_time_s'] <= tx[copy['message_id']]['sent_time_s']
        assert tx[copy['message_id']]['actual_sender_id'] == -1
        for field in ['payload_digest', 'hmac_digest', 'packet_type', 'sequence_no',
                      'created_time_s', 'session_id', 'key_epoch']:
            assert original[field] == copy[field]
        auth = [e for e in audit['security_observations'] if e['message_id'] == copy['message_id']]
        assert any(e['observer_node_id'] == 1 and e['security_state']['application_hmac_failure_reason'] == 'HMAC_MISMATCH' for e in auth)
        assert any(e['message_id'] == copy['message_id'] and e['result']['executed']
                   and e['result']['request']['action'] == 'DROP_PACKET' for e in audit['actions'])
    counts = accounting['attacks'][0]['counts']
    assert counts['sent_attack_count'] == len(rows) <= accounting['business']['origin_business_sent_count']
    assert counts['executed_drop_count'] == counts['detected_report_count'] == len(rows)
    if duration == 3.2:
        assert len(rows) == 5  # .2..1.8 captured, .4..2.0 emitted; end 2.4 exclusive


def test_no_original_no_spoof_copy():
    cfg = config()
    cfg.traffic_specs = []
    runtime = PlatformRuntime(cfg)
    runtime.run_to_completion()
    audit = runtime.runtime_view()['packet_accounting']
    assert audit['causal_evidence']['derivations'] == []
    assert audit['attacks'][0]['counts']['generated_attack_count'] == 0


def test_fdi_sign_then_mutate_subset_and_preserve_tag():
    cfg = config()
    cfg.traffic_specs[0].update(packet_type='TELEMETRY', payload={'altitude_m': 100}, interval_s=.2, count=10)
    cfg.attack_specs[0].update(attack_family='FDI', attack_subtype='TELEMETRY_ABRUPT_CHANGE',
        attacker_node_id=2, parameters={'field': 'altitude_m', 'absolute_offset': .1})
    runtime = PlatformRuntime(cfg)
    runtime.run_to_completion()
    a = runtime.runtime_view()['packet_accounting']
    c = a['causal_evidence']
    signatures = {row['message_id']: row for row in c['signatures']}
    assert len(c['generations']) == 10 and len(c['mutations']) == 9
    for row in c['mutations']:
        before = signatures[row['message_id']]
        assert before['signed'] and before['hmac_digest'] == row['hmac_digest']
        assert before['payload']['altitude_m'] == 100
        assert row['payload']['altitude_m'] == 100.1
    assert a['business']['origin_business_sent_count'] == 10
    assert a['business']['unmodified_business_sent_count'] == 1


def test_eaves_plain_control_is_not_sensitive_exposure():
    from types import SimpleNamespace
    from swarm_sim.packet_accounting import PacketAccounting
    counter = PacketAccounting(config())
    record = SimpleNamespace(plan=SimpleNamespace(attack_id='eve'))
    counter.attacks['eve'] = {'counts': __import__('collections').Counter()}
    for idx, (encrypted, sensitive) in enumerate([(True, True), (False, False), (False, True)]):
        counter.eaves_captured(record, SimpleNamespace(message_id=str(idx), hop_index=0,
            encrypted=encrypted, sensitive=sensitive))
    counts = counter.attack('eve')
    assert counts['captured_frame_count'] == 3
    assert counts['captured_ciphertext_count'] == counts['captured_sensitive_ciphertext_count'] == 1
    assert counts['captured_plaintext_count'] == 2
    assert counts['captured_nonsensitive_plaintext_count'] == 1
    assert counts['plaintext_exposure_count'] == counts['content_recovery_count'] == 1
