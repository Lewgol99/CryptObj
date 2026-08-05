import time
import csv
import os
import pandas

class LatencyMonitor:
    def __init__(self, max_measurements=2000):  
        self._results_list = []  
        self.start = None
        self.stop = None
        self.max_measurements = max_measurements
        self._autosaved = False  

    def start_latency(self):
        self.start = time.perf_counter()
        return self.start

    def stop_latency(self, label=''):
        self.stop = time.perf_counter()
        latency = (self.stop - self.start) * 1000
        measurement = len(self._results_list) + 1
        self._results_list.append({
            'measurement': measurement,
            'label': label,
            'latency_ms': round(latency, 6)
        })
        print(f"Measurement {measurement} [{label}]: {latency:.6f} ms")
        
        if not self._autosaved and len(self._results_list) >= self.max_measurements:
            self.save_file('latency_measurements')
            self._autosaved = True

        return latency

    def reset(self):  
        self._results_list = []
        self._autosaved = False  

    def save_file(self, filename):
        if self._results_list:
            df = pandas.DataFrame(self._results_list)
            df.to_csv(f'{filename}.csv', index=False)

    def append_last(self, filename):
        if not self._results_list:
            return
        row = self._results_list[-1]
        path = f'{filename}.csv'
        write_header = not os.path.exists(path)
        with open(path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['measurement', 'label', 'latency_ms'])
            if write_header:
                writer.writeheader()
            writer.writerow(row)
