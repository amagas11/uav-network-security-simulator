"""Read-only simulator accounting. Never used by detectors or defense policies.

Source messages are unique by run-scoped message_id; air copies by hop and
replay emission ordinal. A decoded arrival is not authentication/business success.
"""
from collections import Counter
from copy import deepcopy
import math
import hashlib
import json


def active_tick_count(config, plan):
    now, count = 0.0, 0
    while now < config.duration_s - 1e-12:
        now = round(min(config.duration_s, now + config.step_s), 9)
        count += int(plan['impact_start_s'] <= now < plan['end_s'])
    return count


class PacketAccounting:
    def __init__(self, config):
        self.config = config
        scheduled = sum(s.get('count', 1) for s in config.traffic_specs)
        automatic = math.ceil(config.duration_s / config.step_s - 1e-9) if config.auto_traffic else 0
        self.business = Counter(planned_business_count=scheduled+automatic,
                                planned_scheduled_business_count=scheduled,
                                planned_auto_business_count=automatic)
        self.messages = {}
        self.seen = set()
        self.attacks = {}
        self.causal = {'scope': 'SIMULATOR_AUDIT_TRUTH', 'generations': [], 'signatures': [], 'mutations': [], 'transmissions': [],
                       'captures': [], 'derivations': [], 'interceptions': [], 'security_observations': [], 'actions': []}
        self._latest_emission = {}

    def add(self, bucket, field, token):
        identity = (id(bucket), field, str(token))
        if identity not in self.seen:
            self.seen.add(identity)
            bucket[field] += 1

    def register_attack(self, plan):
        from dataclasses import asdict
        p = asdict(plan)
        family = p['attack_family']
        entry = {'attack_id': p['attack_id'], 'family': family,
                 'target_node_ids': p['target_node_ids'], 'counts': Counter(),
                 'attack_duration_s': round(p['end_s'] - p['impact_start_s'], 9),
                 'active_tick_count_planned': active_tick_count(self.config, p)}
        if family == 'DOS':
            entry['configured_rate_pps'] = float(p['intensity'].get('value', 60))
            entry['counts']['planned_attack_count'] = math.floor(entry['active_tick_count_planned'] * entry['configured_rate_pps'] * self.config.step_s + 1e-9)
        elif family == 'SPOOFING':
            entry['counts']['planned_attack_count'] = (None if p['parameters'].get('source_copy_mode')
                                                       else entry['active_tick_count_planned'])
        elif family == 'REPLAY':
            entry['counts']['planned_attack_count'] = 1 if not p['parameters'].get('repeat') else None
        self.attacks[p['attack_id']] = entry

    def attack(self, attack_id):
        entry = self.attacks.get(attack_id)
        return entry['counts'] if entry else None

    def business_generated(self, message):
        self.messages[message.message_id] = {'business': True, 'target': message.final_dst_node_id, 'attack_id': None}
        self.add(self.business, 'generated_business_count', message.message_id)
        self.causal['generations'].append({'message_id': message.message_id,
            'source_id': message.origin_node_id, 'target_id': message.final_dst_node_id,
            'created_time_s': message.created_time_s, 'packet_type': message.packet_type,
            'sequence_no': message.sequence_no, 'sensitive': message.sensitive,
            'payload': deepcopy(message.payload)})

    @staticmethod
    def frame_identity(frame):
        # Equality proof without tag bytes or any key.
        digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return {'message_id': frame.message_id, 'claimed_src_id': frame.claimed_src_id,
                'packet_type': frame.packet_type, 'sequence_no': frame.sequence_no,
                'created_time_s': frame.created_time_s, 'session_id': frame.observable_session_id,
                'key_epoch': frame.key_epoch, 'payload_digest': digest(frame.protected_payload),
                'hmac_digest': digest(frame.app_hmac_tag), 'signed': bool(frame.app_hmac_tag),
                'link_id': frame.link_id, 'hop_index': frame.hop_index,
                'sender_id': frame.link_sender_id, 'receiver_id': frame.link_receiver_id,
                'sensitive': frame.sensitive, 'encrypted': frame.encrypted,
                'attack_id': frame.runtime_attack_id}

    def capture_record(self, record, frame, now):
        if record.plan.attack_family in {'SPOOFING', 'FDI'}:
            self.add(self.attack(record.plan.attack_id), 'captured_frame_count', f'{frame.message_id}:{frame.hop_index}')
        self.causal['captures'].append({**self.frame_identity(frame), 'attack_id': record.plan.attack_id,
                                       'family': record.plan.attack_family, 'capture_time_s': now,
                                       'frame_emission_id': self._latest_emission.get((frame.message_id, frame.hop_index))})

    def derived_spoof(self, record, original, frame, captured_s, now):
        self.messages[frame.message_id] = {'business': False, 'target': frame.link_receiver_id,
                                           'attack_id': record.plan.attack_id}
        self.add(self.attack(record.plan.attack_id), 'generated_attack_count', frame.message_id)
        self.causal['derivations'].append({'original': self.frame_identity(original),
            'copy': self.frame_identity(frame), 'capture_time_s': captured_s, 'modified_time_s': now,
            'attacker_id': record.plan.attacker_node_id, 'modified_fields': ['claimed_src_id']})

    def transmission(self, frame, actual_sender, now, emission, decoded):
        self._latest_emission[(frame.message_id, frame.hop_index)] = emission
        self.causal['transmissions'].append({**self.frame_identity(frame), 'actual_sender_id': actual_sender,
            'sent_time_s': now, 'emission_id': emission, 'decoded': bool(decoded)})
        if frame.hop_index == 1:
            for interception in self.causal['interceptions']:
                if interception['message_id'] == frame.message_id:
                    interception.update(replacement_emission_id=emission, replacement_sent_time_s=now,
                        replacement_frame=self.frame_identity(frame), target_decoded=bool(decoded))

    def observe_event(self, event):
        if event.get('event_type') != 'AUTH_RESULT':
            return
        features = event.get('online_features', {})
        self.causal['security_observations'].append({'event_id': event['event_id'],
            'observer_node_id': event['observer_node_id'], 'event_time_s': event.get('sim_time_s'),
            'message_id': event.get('message_id'), 'extensions': deepcopy(event.get('extensions', {})),
            'packet': deepcopy(features.get('packet')), 'security_state': deepcopy(features.get('security_state'))})

    def attack_generated(self, message, record):
        info = self.messages.setdefault(message.message_id, {'business': False, 'target': message.final_dst_node_id})
        info['attack_id'] = record.plan.attack_id
        self.add(self.attack(record.plan.attack_id), 'generated_attack_count', message.message_id)

    def attempt(self, record, token):
        self.add(self.attack(record.plan.attack_id), 'attempt_count', token)

    def fdi_eligible(self, record, message):
        self.add(self.attack(record.plan.attack_id), 'eligible_count', message.message_id)

    def fdi_modified(self, record, message, changed, now_s=None, original=None):
        if changed:
            self.attack_generated(message, record)
            self.add(self.attack(record.plan.attack_id), 'modified_count', message.message_id)
            self.causal['mutations'].append({'message_id': message.message_id, 'modified_time_s': now_s if now_s is not None else message.created_time_s,
                'original_payload': deepcopy(original), 'sequence_no': message.sequence_no,
                'changed_fields': [key for key in sorted(set(original or {}) | set(message.payload)) if (original or {}).get(key) != message.payload.get(key)],
                'hmac_recomputed': False,
                'payload': deepcopy(message.payload), 'hmac_digest': hashlib.sha256(json.dumps(message.app_hmac_tag).encode()).hexdigest(),
                'attack_id': record.plan.attack_id, 'stage': record.plan.parameters.get('injection_mode', 'POST_HMAC_PRE_TRANSMISSION')})

    def signed(self, message, now_s=None):
        if message.message_id not in self.messages or not self.messages[message.message_id].get('business'):
            return
        self.causal['signatures'].append({'message_id': message.message_id, 'signed_time_s': now_s if now_s is not None else message.created_time_s,
            'hmac_digest': hashlib.sha256(json.dumps(message.app_hmac_tag).encode()).hexdigest(),
            'signed': bool(message.app_hmac_tag), 'payload': deepcopy(message.payload)})

    def air_sent(self, frame, replay_record=None, emission=None):
        info = self.messages.get(frame.message_id, {})
        if replay_record is not None:
            self.add(self.attack(replay_record.plan.attack_id), 'sent_attack_count', emission)
            return
        if frame.hop_index == 0:
            if info.get('business'):
                self.add(self.business, 'origin_business_sent_count', frame.message_id)
                if not info.get('attack_id'):
                    self.add(self.business, 'unmodified_business_sent_count', frame.message_id)
            if info.get('attack_id'):
                self.add(self.attack(info['attack_id']), 'sent_attack_count', frame.message_id)
        elif info.get('attack_id') and self.attacks[info['attack_id']]['family'] == 'FDI':
            self.add(self.attack(info['attack_id']), 'sent_attack_count', frame.message_id)

    def arrived(self, frame, replay_record=None, emission=None):
        info = self.messages.get(frame.message_id, {})
        if replay_record is not None:
            self.add(self.attack(replay_record.plan.attack_id), 'target_received_count', emission)
            return
        if frame.link_receiver_id != info.get('target'):
            return
        if info.get('business'):
            self.add(self.business, 'target_business_received_count', frame.message_id)
        if info.get('attack_id'):
            self.add(self.attack(info['attack_id']), 'target_received_count', frame.message_id)

    def replay_captured(self, attack_id, frame):
        self.add(self.attack(attack_id), 'captured_frame_count', f'{frame.message_id}:{frame.hop_index}')

    def eaves_captured(self, record, frame):
        bucket = self.attack(record.plan.attack_id)
        token = f'{frame.message_id}:{frame.hop_index}'
        self.add(bucket, 'captured_frame_count', token)
        self.add(bucket, 'captured_ciphertext_count' if frame.encrypted else 'captured_plaintext_count', token)
        field = 'captured_' + ('sensitive' if frame.sensitive else 'nonsensitive') + ('_ciphertext_count' if frame.encrypted else '_plaintext_count')
        self.add(bucket, field, token)
        if not frame.encrypted and not frame.sensitive and getattr(frame, 'packet_type', None) == 'SKG_CONTROL':
            self.add(bucket, 'captured_protocol_control_plaintext_count', token)
        if frame.sensitive and not frame.encrypted:
            self.add(bucket, 'plaintext_exposure_count', token)
            self.add(bucket, 'content_recovery_count', token)

    def detection(self, node_id, frame, category, result):
        # Observation happens AFTER the existing detector and defense executed.
        self.causal['actions'].append({'detector_node_id': node_id, 'message_id': getattr(frame, 'message_id', None),
            'category': category, 'result': deepcopy(result)})
        for attack_id, entry in self.attacks.items():
            is_dos = entry['family'] == 'DOS' and category == 'DOS'
            matches = frame is not None and frame.runtime_attack_id == attack_id
            bucket = entry['counts']
            token = result['request']['request_id']
            if is_dos:
                field = 'target_dos_alarm_count' if node_id in entry['target_node_ids'] else 'secondary_dos_alarm_count'
                self.add(bucket, field, token)
            if not matches or node_id not in entry['target_node_ids'] or category not in {'AUTH_FAILURE', 'REPLAY'}:
                continue
            self.add(bucket, 'detected_report_count', token)
            if category == 'AUTH_FAILURE':
                self.add(bucket, 'hmac_failure_count', token)
            if result.get('executed') is True:
                self.add(bucket, 'executed_action_count', token)
                if result['request']['action'] == 'DROP_PACKET':
                    self.add(bucket, 'executed_drop_count', token)

    def snapshot(self, run_id):
        base_fields = ['planned_business_count', 'planned_scheduled_business_count', 'planned_auto_business_count', 'generated_business_count', 'origin_business_sent_count', 'unmodified_business_sent_count', 'target_business_received_count']
        attack_fields = ['attempt_count','generated_attack_count','eligible_count','modified_count','sent_attack_count','target_received_count','detected_report_count','hmac_failure_count','executed_action_count','executed_drop_count','captured_frame_count','captured_ciphertext_count','captured_plaintext_count','captured_sensitive_ciphertext_count','captured_nonsensitive_plaintext_count','plaintext_exposure_count','content_recovery_count','target_dos_alarm_count','secondary_dos_alarm_count']
        attack_fields.extend(['captured_sensitive_plaintext_count', 'captured_nonsensitive_ciphertext_count', 'captured_protocol_control_plaintext_count'])
        return {'schema_version':'packet-accounting-v1', 'run_id':run_id,
                'scope':'SIMULATOR_GENERATION_AND_EXECUTION_ACCOUNTING',
                'simulation_duration_s':self.config.duration_s,
                'causal_evidence': deepcopy(self.causal),
                'business':{k:self.business[k] for k in base_fields},
                'attacks':[{**deepcopy(entry), 'counts':{**{k:entry['counts'][k] for k in attack_fields}, **dict(entry['counts'])}} for entry in self.attacks.values()]}
