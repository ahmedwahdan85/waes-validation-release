"""Print and save the benchmark output from the ZCU102 UART0.
Usage: python scripts/uart_log.py COMx      (the first of the board's USB-UART ports)"""
import os
import sys
import time

import serial

port = sys.argv[1]
log = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results',
                   time.strftime('ps_bench_%Y%m%d_%H%M%S.txt'))
os.makedirs(os.path.dirname(log), exist_ok=True)
with serial.Serial(port, 115200, timeout=1) as s, open(log, 'w') as f:
    print(f'listening on {port}, saving to {os.path.abspath(log)}')
    while True:
        line = s.readline().decode(errors='replace').rstrip()
        if not line:
            continue
        print(line)
        f.write(line + '\n')
        f.flush()
        if line in ('done', 'VERIFY FAILED, benchmark not run'):
            break
