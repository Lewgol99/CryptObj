import time
import pandas

class DSThroughputMonitor:
    def __init__(self, max_measurements=1000):
        self._results_list = [] 
        self.start = None
        self.stop = None
        self.max_measurements = max_measurements

    def start_throughput(self):
        self.start = time.perf_counter()
        return self.start

    def stop_throughput(self, bytes_size, label=''):
        self.stop = time.perf_counter()
        elapsed = (self.stop - self.start)
        throughput = (bytes_size / elapsed) / (1024 * 1024)
        measurement = len(self._results_list) + 1
        self._results_list.append({
            'measurement': measurement,
            'label': label,
            'throughput_MBs': round(throughput, 3)
        })
        print(f"Measurement {measurement} [{label}]: {throughput:.3f} MB/s")

        # Fixed: save only at 1000 measurements not every packet
        if len(self._results_list) >= self.max_measurements:
            self.save_file('ds_throughput_measurements')

        return throughput

    def reset(self):  # Added: reset between test runs
        self._results_list = []

    def save_file(self, filename):
        if self._results_list:
            df = pandas.DataFrame(self._results_list)
            df.to_csv(f'{filename}.csv', index=False)
