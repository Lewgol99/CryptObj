#!/bin/bash
for i in {1...1000}; do
ping 10.100.0.166 -c | grep 'Reply' > network_latency.csv
done
