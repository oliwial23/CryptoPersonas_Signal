import time
import json
import subprocess
import os
import glob
from datetime import datetime
import nbformat
from nbconvert.preprocessors import ExecutePreprocessor
import shutil

OUTPUT_FILE = "experiments/scan_timing_log.json"
NUM_ITERATIONS = 100
GROUP_ID = "YOUR_GROUP_ID"
THREAD = "experiment"

# Clear all existing experiment files
def clean_previous_results():
    folders = [
               'json_files/pseudo_msg', 
               'json_files/scan' 
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
clean_previous_results()

for subdir in [
               'json_files/pseudo_msg',
               'json_files/scan']:
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

def get_timing_log(path):
    return os.path.exists(os.path.join(path, "timings.jsonl"))

def get_timing_features_log():
    path = 'json_files/scan'
    return os.path.exists(os.path.join(path, "features_timings.jsonl"))

def get_timing_verify_log():
    path = 'json_files/scan'
    return os.path.exists(os.path.join(path, "verify_timings.jsonl"))

def wait(seconds):
    print(f"Waiting {seconds} seconds...\n")
    time.sleep(seconds)


def assert_all_timings_written():
    paths = [ 
             'json_files/pseudo_msg',
             'json_files/scan'
            ]
    if not all([get_timing_log(path) for path in paths]):
        raise RuntimeError("❌ Missing one or more timing files!")
    print("✅ All timing files written correctly.")


def run_notebook(path):
    print("📊 Running analysis notebook...")
    with open(path) as f:
        nb = nbformat.read(f, as_version=4)
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(nb, {'metadata': {'path': './'}})
    print("✅ Notebook executed: scan_analysis.ipynb")


for l in range(1, NUM_ITERATIONS + 1):
    iteration_log = {
        "iteration": l,
        "timestamp": datetime.utcnow().isoformat(),
        "actions": {}
    }
    # 1. Optional join first
    join_command = ["cargo", "run", "--bin", "personas", "--release", "join"]
    print("🧪 Running join command...")
    run_command(join_command)

    # Generate another pseudonym for authorship check
    print("Generating new pseudonym...")
    run_command(["cargo", "run", "--bin", "personas", "--release", "gen-pseudo"])

    print(f"📨 Iteration {l}: Sending standard post...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "post-pseudo",
        "-m", f"Message: {l}",
        "-g", GROUP_ID,
        "-i", "1"
    ])
    iteration_log["actions"]["standard_post"] = {"duration": duration, "success": success, "error": error if not success else None}
    wait(3)

    print(f"📨 Iteration {l}: Scanning...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "scan",
    ])
    iteration_log["actions"]["scan"] = {"duration": duration, "success": success, "error": error if not success else None}

    try:
        assert_all_timings_written()
    except RuntimeError as e:
        print(f"⚠️ Iteration {l} warning: {e}")
        iteration_log["timing_check_error"] = str(e)

    get_timing_features_log()

    get_timing_verify_log()

    append_log(iteration_log)
    print(f"✅ Iteration {l} complete.")


# 4. Analyze results
# run_notebook("scan_analysis.ipynb")