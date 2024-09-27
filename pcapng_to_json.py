#!/usr/bin/env python3

import json
from sys import argv
from pathlib import Path
from pcapng_utils.tshark import Tshark

input_file = Path(argv[1])
output_file = input_file.with_suffix('.json')
assert input_file != output_file

traffic = Tshark().load_traffic(input_file)
with output_file.open('w') as fp:
    json.dump(traffic.list_packets, fp, indent=2)
