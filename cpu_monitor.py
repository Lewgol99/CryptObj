import psutil
import pandas as pd
import time
import threading

class CPUMonitor:
    def __init__(self):
        self.results_list = []
        self.running = False
        self.thread = None

    def start_monitoring(self):
        self.running = True
        self.thread = threading.Thread(target=self.collect_cpu)
        self.thread.start()
        return True

    def collect_cpu(self):
        for i in range(1000):  # Take 1000 measurements
            if not self.running:
                break
            cpu_percent = psutil.cpu_percent(interval=1)
            data = {
                'measurement': i + 1,  # Added measurement number
                'cpu_percent': cpu_percent
            }
            self.results_list.append(data)
            
            # SAVE IMMEDIATELY after each measurement (like latency monitor)
            self.save_file('cpu_measurements')
            print(f"CPU measurement {i + 1}: {data['cpu_percent']}% - CSV updated")
            
            time.sleep(5)  # Wait 30 seconds between measurements

    def stop_monitoring(self):
        self.running = False
        if self.thread:
            self.thread.join()
        
        # FORCE SAVE when stopped (like latency monitor)
        self.save_file('pysyncobj+_cpu_measurements')
        print(f"🛑 CPU monitoring stopped - Final CSV saved with {len(self.results_list)} measurements")
        return True

    # Create a function to save the generated results to a csv file with an iteration and results column 
    def save_file(self, filename):
        if self.results_list:  # Only save if we have data
            df = pd.DataFrame(self.results_list)
            df.to_csv(f'{filename}.csv', index=False)
            # Don't print every save to avoid spam, just confirm it's working
        return True
