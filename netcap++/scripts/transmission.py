#!/bin/python3

import sys
import csv
from dataclasses import dataclass, field

if len(sys.argv) <= 2:
    print("Please specify a file and the window duration im ms")
    sys.exit()

file_path = sys.argv[1]
window_duration = sys.argv[2]

@dataclass(order=True)
class Entry:
    sort_index: int = field(init=False)
    window_start: int
    payload_size: int

    def __post_init__(self):
        self.sort_index = self.window_start

data = []
with open(file_path) as csvfile:
    reader = csv.reader(csvfile, delimiter=';')
    for row in reader:
        data.append(row)

del data[0]

data = [Entry(int(entry[2]), int(entry[4])) for entry in data]

data.sort()

total_traffic = sum([entry.payload_size for entry in data])
total_duration = (data[-1].window_start - data[0].window_start + 1000) / 1000

transmission_rate = total_traffic / total_duration
print(int(transmission_rate))