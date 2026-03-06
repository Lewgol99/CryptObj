import time
import pandas

class DSLatencyMonitor:
    _results_list = []  # Static list shared across all instances

    def __init__(self, max_measurements=10):
        self.start = None
        self.stop = None
        self.max_measurements = max_measurements

    def start_latency(self):
        self.start = time.perf_counter()  # perf_counter is far more precise than time.time()
        return self.start

    def stop_latency(self, label=''):
        self.stop = time.perf_counter()
        latency = (self.stop - self.start) * 1000  # convert to milliseconds
        measurement = len(LatencyMonitor._results_list) + 1

        LatencyMonitor._results_list.append({
            'measurement': measurement,
            'label': label,
            'latency_ms': round(latency, 6)
        })

        print(f"Measurement {measurement} [{label}]: {latency:.6f} ms")
        self.save_file('ds_latency_measurements')
        return latency

    def save_file(self, filename):
        if LatencyMonitor._results_list:
            df = pandas.DataFrame(LatencyMonitor._results_list)
            df.to_csv(f'{filename}.csv', index=False)
