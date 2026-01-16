import time
import pandas

class LatencyMonitor:
    _instance = None
    _results_list = []  # Static list to store all measurements
    
    def __init__(self, max_measurements=10):
        self.start = None
        self.stop = None 
        self.max_measurements = max_measurements

# Create a function to start the timer using the time() method 
    
    def start_latency(self):
        self.start = time.time()
        return self.start
    
# Create a function to stop the timer using the time() method 

    def stop_latency(self):
        self.stop = time.time()
        latency = (self.stop - self.start) * 1000 # Use * 1000 to generate the results in milliseconds 
        measurement = len(LatencyMonitor._results_list) + 1
        LatencyMonitor._results_list.append({
            'measurement': measurement,  # Added measurement number
            'latency': latency
        })
        print(f"Measurement {measurement}: {latency:.3f} milliseconds")
        self.save_file('latency_measurements')
        return self.stop
    
# Create a function to save the generated results to a csv file with an iteration and results coloumn 

    def save_file(self, node_id):
       if LatencyMonitor._results_list:
        df = pandas.DataFrame(LatencyMonitor._results_list)
        df.to_csv(f'{node_id}.csv', index=False)
        return
