#!/usr/bin/env python3
"""Validate a completed PRE collection trace. Does not infer protocol fields."""
import argparse
import collections
import json


def check(path):
    tags = {0}
    instructions = set()
    counts = collections.Counter()
    summary = None
    previous_seq = 0
    with open(path, encoding='utf-8') as stream:
        for line_no, line in enumerate(stream, 1):
            record = json.loads(line)
            kind = record['type']
            counts[kind] += 1
            if line_no == 1 and (kind != 'header' or record.get('schema') != 1):
                raise ValueError('missing schema 1 header')
            if summary is not None:
                raise ValueError('records after final summary')
            if kind == 'tag':
                if record['id'] in tags:
                    raise ValueError('duplicate tag definition')
                tags.add(record['id'])
            elif kind == 'instruction':
                if record['id'] in instructions:
                    raise ValueError('duplicate instruction definition')
                instructions.add(record['id'])
            elif kind in ('step', 'control'):
                if record['ins'] not in instructions:
                    raise ValueError('undefined instruction')
                for operand in record['operands']:
                    used = operand['before'] + operand.get('after', [])
                    used += [operand.get('address_tag', 0)]
                    if any(tag not in tags for tag in used):
                        raise ValueError('undefined provenance tag')
            elif kind == 'model':
                if record['return_tag'] not in tags or record['model'] != 'comparison_return':
                    raise ValueError('invalid comparison model')
            elif kind == 'output':
                if (len(record['bytes']) != 2 * len(record['tags']) or
                        record['offset'] + len(record['tags']) > record['returned'] or
                        any(tag not in tags for tag in record['tags'])):
                    raise ValueError('invalid output snapshot')
            if 'seq' in record:
                if record['seq'] != previous_seq + 1:
                    raise ValueError('non-contiguous dynamic sequence')
                previous_seq = record['seq']
            if kind == 'summary':
                summary = record
    if summary is None:
        raise ValueError('missing final summary: trace may be incomplete')
    if summary['events'] != previous_seq or summary['inputs'] != counts['input']:
        raise ValueError('summary does not match events')
    return {'records': dict(counts), 'summary': summary}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace')
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.trace), ensure_ascii=False, indent=2))
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f'invalid trace: {error}\n')
