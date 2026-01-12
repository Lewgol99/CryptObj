from psutil import virtual_memory
import pandas as pd
import time
import threading

class MemoryMonitor:
    def __init__(self):
        self.results_list = []
        self.running = False
        self.thread = None

    def start_monitoring(self):
        self.running = True
        self.thread = threading.Thread(target=self.collect_memory)
        self.thread.start()
        return True

    def collect_memory(self):
        for i in range(1000):  # Take 1000 measurements
            if not self.running:
                break
            memory = virtual_memory()
            data = {
                'measurement': i + 1,  # Added measurement number
                'memory_mb': round(memory.used/1024**2, 1), # record memory in MB (use **3 for GB)
                'memory_percent': memory.percent
            }
            self.results_list.append(data)
            
            # SAVE IMMEDIATELY after each measurement (like latency monitor)
            self.save_file('memory_measurements')
            print(f"Memory measurement {i + 1}: {data['memory_mb']}MB ({data['memory_percent']}%) - CSV updated")
            
            time.sleep(5)  # Wait 30 seconds between measurements

    def stop_monitoring(self):
        self.running = False
        if self.thread:
            self.thread.join()
        
        # FORCE SAVE when stopped (like latency monitor)
        self.save_file('memory_measurements')
        print(f"🛑 Memory monitoring stopped - Final CSV saved with {len(self.results_list)} measurements")
        return True

    # Create a function to save the generated results to a csv file 
    def save_file(self, filename):
        if self.results_list:  # Only save if we have data
            df = pd.DataFrame(self.results_list)
            df.to_csv(f'{filename}.csv', index=False)
            # Don't print every save to avoid spam, just confirm it's working
        return True
