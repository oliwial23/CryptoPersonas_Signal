import time
import json
import subprocess
import os
import glob
from datetime import datetime
import nbformat
from nbconvert.preprocessors import ExecutePreprocessor
import shutil

OUTPUT_FILE = "experiments/fold_timing_log.json"
NUM_ITERATIONS = 10
GROUP_ID = "YOUR_GROUP_ID"
THREAD = "experiment"

# Clear all existing experiment files
def clean_previous_results():
    folders = [
               'json_files/pseudo_msg', 
               'json_files/fold' 
               ]
    for folder in folders:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"❌ Failed to delete {file_path}: {e}")
        else:
            os.makedirs(folder, exist_ok=True)

    # Optional: clear overall experiment log
    if os.path.exists(OUTPUT_FILE):
        try:
            os.remove(OUTPUT_FILE)
        except Exception as e:
            print(f"❌ Failed to delete {OUTPUT_FILE}: {e}")

    print("🧹 Cleaned all previous timing files.")

# Run cleanup first
# clean_previous_results()

for subdir in [
               'json_files/pseudo_msg',
               'json_files/fold']:
    os.makedirs(subdir, exist_ok=True)

os.makedirs("experiments", exist_ok=True)

def wait(seconds):
    print(f"Waiting {seconds} seconds...\n")
    time.sleep(seconds)


def run_command(command):
    start = time.time()
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        return time.time() - start, False, e.stderr.decode()
    return time.time() - start, True, ""

def append_log(entry):
    try:
        with open(OUTPUT_FILE, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = []
    
    data.append(entry)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_timing_log():
    path = 'json_files/pseudo_msg'
    return os.path.exists(os.path.join(path, "timings.jsonl"))

def get_timing_step_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "step_timings.jsonl"))

def get_timing_latency_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "latency_timings.jsonl"))

def get_timing_verify_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "verify_timings.jsonl"))

def get_timing_proof_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "proof_timings.jsonl"))

def get_timing_size_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "proof_size.jsonl"))

def get_timing_body_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "body_timings.jsonl"))

def get_timing_params_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "params_timings.jsonl"))

def get_timing_deserialize_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "deserialize_timings.jsonl"))

def get_timing_bulletin_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "bul_timings.jsonl"))

def get_timing_handler_log():
    path = 'json_files/fold'
    return os.path.exists(os.path.join(path, "handler_timings.jsonl"))

def wait(seconds):
    print(f"Waiting {seconds} seconds...\n")
    time.sleep(seconds)

def run_notebook(path):
    print("📊 Running analysis notebook...")
    with open(path) as f:
        nb = nbformat.read(f, as_version=4)
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(nb, {'metadata': {'path': './'}})
    print("✅ Notebook executed: fold_analysis.ipynb")

for i in range (1, 2):
    # 1. Optional join first
    join_command = ["cargo", "run", "--bin", "personas", "--release", "join"]
    print("🧪 Running join command...")
    run_command(join_command)

    # Generate another pseudonym for authorship check
    print("Generating new pseudonym...")
    run_command(["cargo", "run", "--bin", "personas", "--release", "gen-pseudo"])

    iteration_log = {
        "iteration": i,
        "timestamp": datetime.utcnow().isoformat(),
        "actions": {}
    }

    # k = 100
    for j in range(1, 101):
        print(f"📨 Iteration {j}: Sending standard post...")
        duration, success, error = run_command([
            "cargo", "run", "--bin", "personas", "--release", "post-pseudo",
            "-m", f"Message: {i*j}",
            "-g", GROUP_ID,
            "-i", "1"
        ])
        iteration_log["actions"]["standard_post"] = {"duration": duration, "success": success, "error": error if not success else None}
        wait(1)

    print(f"📨 Iteration {i}: Scanning...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "scan-folding",
    ])
    iteration_log["actions"]["scan-folding"] = {"duration": duration, "success": success, "error": error if not success else None}

    get_timing_log()

    get_timing_step_log()

    get_timing_latency_log()

    get_timing_verify_log()

    get_timing_proof_log()

    get_timing_size_log()

    append_log(iteration_log)
    print(f"✅ Iteration {i} complete.")


# 4. Analyze results
# run_notebook("fold_analysis.ipynb")


    