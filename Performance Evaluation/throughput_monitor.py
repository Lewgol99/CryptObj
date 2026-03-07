import time
import pandas

class ThroughputMonitor:
    _results_list = []  # Static list shared across all instances

    def __init__(self, max_measurements=1000):
        self.start = None
        self.stop = None
        self.max_measurements = max_measurements

    def start_throughput(self):
        self.start = time.perf_counter()  # perf_counter is far more precise than time.time()
        return self.start

    def stop_throughput(self, bytes_size, label=''):
        self.stop = time.perf_counter()
        elapsed = (self.stop - self.start)
        throughput = (bytes_size / elapsed) / (1024 * 1024)
        measurement = len(ThroughputMonitor._results_list) + 1

        ThroughputMonitor._results_list.append({
            'measurement': measurement,
            'label': label,
            'throughput_MBs': round(throughput, 3)
        })

        print(f"Measurement {measurement} [{label}]: {throughput:.3f} MB/s")
        self.save_file('throughput_measurements')
        return throughput

    def save_file(self, filename):
        if ThroughputMonitor._results_list:
            df = pandas.DataFrame(ThroughputMonitor._results_list)
            df.to_csv(f'{filename}.csv', index=False)
