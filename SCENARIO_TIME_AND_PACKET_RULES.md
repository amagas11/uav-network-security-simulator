# V21_FINAL simulation timing

V21 is read-only. V21_FINAL retains its live simulation timing, not recorded playback.

Simulation duration: 3.2–30 s (Eaves default 4 s), aligned to each scenario step (0.2 s; Eaves 0.1 s). Presets: original default, 5, 10, 20, 30 s. Wall-clock runtime is not simulation time. Inputs affect only the next run; current duration is recovered from run_config after refresh.

Business schedule: t=start+n*interval, with count=floor((duration-buffer-start)/interval)+1 for extended scenarios. Original defaults remain unchanged.

|Scenario|Default duration / step|Business start / interval / scheduled count|Buffer|Attack window|
|---|---|---|---|---|
|Spoofing|3.2 / 0.2|0.2 / 0.4 / 6|1.0|[0.4,2.4)|
|FDI|3.2 / 0.2|0.2 / 0.2 / 10|1.2|[0.4,2.4)|
|DoS|3.2 / 0.2|0.2 / 0.3 / 8|0.9|[0.4,2.0)|
|Eaves|4.0 / 0.1|0.1 / 0.2 / 18|0.5|[0.1,3.8)|
|Replay|3.2 / 0.2|0.2 / single / 1|observation only|Immediate 0.6; delayed 0.4 + 0.8 delay; old-session 0.8 after rotation 0.6|

Runtime clock rounds to 9 decimals. Attack windows include start and exclude end. Spoofing/FDI extended windows scale by duration/default and align to the tick. Eaves retains handshake startup and extends its end to duration-0.2. Replay stays single-shot and retains capture-before-replay/session rotation/freshness sequencing.

Formal Spoofing uses source_copy_mode=LEGITIMATE_FRAME_COPY, legitimate_source_id=2. Only actual scheduled-business first-hop TX frames are observable originals. Capture starts at scheduled_start; a copy may be emitted only on a later active tick, before exclusive end. Each original message_id is consumed once. Production default: six originals sent at .2/.6/1.0/1.4/1.8/2.2; five copies emitted at .4/.8/1.2/1.6/2.0. The last capture at 2.2 would wait until tick 2.4, which is outside the exclusive attack end; no extra copy is fabricated. Extending the run extends business and attack schedules, not a replay loop. Legacy API plans without this mode retain their separately documented external-generated model for backward compatibility; they are not the formal source-copy scene.

Formal FDI uses External's LEGITIMATE_FRAME_COPY_INJECTION mode: the signed original is sent normally, captured, and a separately identified modified copy is injected on a later active tick. The original is not blocked or replaced. The default ten source telemetry messages and nine derived copies are separate counting sets. Historical POST_HMAC_PRE_TRANSMISSION and on-path replacement modes remain compatibility paths, not the production frontend model.

DoS duration is independent: start 0.4, end=start+attack duration, at least 0.4 s observation remains. Rate 9–500 pps, attack duration tick-aligned, at most 5000 generated flood packets per demo. No silent clamping. Fractional quota after tick n is floor(n*pps*step+1e-9); each tick emits the increase in quota. Thus 80/500 pps ×1.6 produce 128/800, while 9 pps produces 14 (not 16).

This seconds-to-30-seconds interactive demo is not the separate 10000-business/500-attack formal workload validation.
