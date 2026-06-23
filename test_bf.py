import os
import time

log_file = "/tmp/fake_traefik.log"

with open(log_file, "a") as f:
    for i in range(6):
        f.write('99.99.99.99 - - [23/Jun/2026:15:45:00 +0200] "GET / HTTP/1.1" 401 123\n')
        f.flush()
        time.sleep(0.1)
