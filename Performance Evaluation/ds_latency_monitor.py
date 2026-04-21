import time
import pandas

class DSLatencyMonitor:
    def __init__(self, max_measurements=1000):  
        self._results_list = []  
        self.start = None
        self.stop = None
        self.max_measurements = max_measurements

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

        # Fixed: save only at 1000 measurements not every packet
        if len(self._results_list) >= self.max_measurements:
            self.save_file('ds_latency_measurements')

        return latency

    def reset(self):  # Added: reset between test runs
        self._results_list = []

    def save_file(self, filename):
        if self._results_list:
            df = pandas.DataFrame(self._results_list)
            df.to_csv(f'{filename}.csv', index=False)
