import subprocess, sys

pattern = r"\[PAYLOAD\]|\[IDENTITY\]|\[NODE-MEMORY\]|\[RAFT-DELTA\]|RAFT LOG ENTRY|addValue\("

result = subprocess.run(["grep", "-E", pattern, sys.argv[1]], capture_output=True, text=True)

with open(sys.argv[2], "w") as f:
    f.write(result.stdout)
