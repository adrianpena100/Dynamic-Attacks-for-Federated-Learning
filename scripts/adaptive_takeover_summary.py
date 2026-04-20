#!/usr/bin/env python3
import json
from collections import Counter
from pathlib import Path

import pandas as pd


BASE = Path('/Users/adrianpena/Documents/Thesis/Experimental/dynamic_fl/logs/sweeps')


def main() -> None:
    sweeps = list(BASE.glob('*_thesis_full__2026-03-05_15-38-03'))
    raw_counter: Counter[str] = Counter()
    primitive_counter: Counter[str] = Counter()

    adaptive_runs = 0
    adaptive_events = 0

    for sweep in sweeps:
        settings_path = sweep / 'sweep_settings.csv'
        if not settings_path.exists():
            continue

        settings = pd.read_csv(settings_path)
        if 'attack_mode' not in settings.columns or 'run_folder' not in settings.columns:
            continue

        adaptive = settings[settings['attack_mode'].astype(str) == 'adaptive']
        for _, row in adaptive.iterrows():
            run_dir = sweep / str(row['run_folder'])
            log_path = run_dir / 'summaries' / 'attack_log.jsonl'
            if not log_path.exists():
                continue

            adaptive_runs += 1
            with log_path.open('r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue

                    name = rec.get('attack_name') or (rec.get('attack_details') or {}).get('attack_name')
                    if not name or name == 'none':
                        continue

                    name = str(name)
                    raw_counter[name] += 1
                    adaptive_events += 1

                    for primitive in name.split('+'):
                        primitive = primitive.strip()
                        if primitive and primitive != 'none':
                            primitive_counter[primitive] += 1

    print('ADAPTIVE_RUNS', adaptive_runs)
    print('ADAPTIVE_EVENTS', adaptive_events)

    print('\nTOP_RAW_ATTACK_NAMES')
    for name, count in raw_counter.most_common(15):
        print(name, count)

    print('\nTOP_PRIMITIVES_SPLIT')
    for name, count in primitive_counter.most_common(15):
        print(name, count)


if __name__ == '__main__':
    main()
