import time
import json
import subprocess
import os
import glob
from datetime import datetime
import nbformat
from nbconvert.preprocessors import ExecutePreprocessor
import shutil

OUTPUT_FILE = "experiments/timing_log.json"
NUM_ITERATIONS = 100
GROUP_ID = "YOUR_GROUP_ID"
THREAD = "experiment"

# Clear all existing experiment files
def clean_previous_results():
    folders = [ 
               'json_files/anon_msg',
               'json_files/author', 
               'json_files/rate_pseudo', 
               'json_files/pseudo_msg', 
               'json_files/pseudo_vote', 
               'json_files/badge', 
               #'json_files/ban', 
               'json_files/rep',
               'json_files/scan']
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

for subdir in ['json_files/anon_msg',
               'json_files/author', 
               'json_files/rate_pseudo', 
               'json_files/pseudo_msg', 
               'json_files/pseudo_vote', 
               'json_files/badge',
               # 'json_files/ban', 
               'json_files/rep',
               'json_files/scan']:
    os.makedirs(subdir, exist_ok=True)

os.makedirs("experiments", exist_ok=True)


def wait(seconds):
    print(f"Waiting {seconds} seconds...\n")
    time.sleep(seconds)


def get_latest_zkpair_timestamp():
    with open("server/signal_zkpair_log.jsonl", "r") as f:
        lines = f.readlines()
        if not lines:
            return None
        last_entry = json.loads(lines[-1])
        return last_entry.get("timestamp")


def get_latest_poll_timestamp():
    with open("server/poll_log.jsonl", "r") as f:
        lines = f.readlines()
        if not lines:
            return None
        last_entry = json.loads(lines[-1])
        return last_entry.get("timestamp")


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

def get_timing_features_log(path):
    return os.path.exists(os.path.join(path, "features_timings.jsonl"))

def get_timing_verify_log(path):
    return os.path.exists(os.path.join(path, "verify_timings.jsonl"))


def get_timing_call_cb_log():
    path = 'json_files/rep'
    return os.path.exists(os.path.join(path, "call_timings.jsonl"))


def get_timing_epoch_log():
    path = 'json_files/rep'
    return os.path.exists(os.path.join(path, "epoch_timings.jsonl"))


def assert_all_timings_written():
    paths = [
             'json_files/anon_msg',  
             'json_files/author', 
             'json_files/rate_pseudo', 
             'json_files/pseudo_msg', 
             'json_files/pseudo_vote', 
             'json_files/badge',
             'json_files/scan'
            ]
    if not all([get_timing_log(path) for path in paths]):
        raise RuntimeError("❌ Missing one or more timing files!")
    print("✅ All timing files written correctly.")

def assert_all_timings_features_written():
    paths = [
             'json_files/anon_msg',
             'json_files/author', 
             'json_files/rate_pseudo', 
             'json_files/pseudo_msg', 
             'json_files/pseudo_vote', 
             'json_files/badge',
             # 'json_files/ban', 
             'json_files/rep',
             'json_files/scan'
            ]
    if not all([get_timing_features_log(path) for path in paths]):
        raise RuntimeError("❌ Missing one or more timing files!")
    print("✅ All timing files written correctly.")

def assert_all_timings_verify_written():
    paths = ['json_files/anon_msg',
             'json_files/author', 
             'json_files/rate_pseudo', 
             'json_files/pseudo_msg', 
             'json_files/pseudo_vote', 
             'json_files/badge',
             'json_files/scan'
            ]
    if not all([get_timing_verify_log(path) for path in paths]):
        raise RuntimeError("❌ Missing one or more timing files!")
    print("✅ All timing files written correctly.")

def run_notebook(path):
    print("📊 Running analysis notebook...")
    with open(path) as f:
        nb = nbformat.read(f, as_version=4)
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(nb, {'metadata': {'path': './'}})
    print("✅ Notebook executed: experiment_analysis.ipynb")

# 1. Optional join first
join_command = ["cargo", "run", "--bin", "personas", "--release", "join"]
print("🧪 Running join command...")
run_command(join_command)

# Generate another pseudonym for authorship check
print("Generating new pseudonym...")
run_command(["cargo", "run", "--bin", "personas", "--release", "gen-pseudo"])

# Generate another pseudonym for authorship check
print("Generating new pseudonym...")
run_command(["cargo", "run", "--bin", "personas", "--release", "gen-pseudo"])

# Generate a new thread context
new_context_command = [
    "cargo", "run",  "--bin",  "personas", "--release", "new-thread-cxt", 
    "-c",  THREAD
]
print("Running new context command...")
run_command(new_context_command)

# Get the existing contexts
get_context_command = [
    "cargo", "run",  "--bin",  "personas", "--release", "get-contexts" 
]
print("Running get context command...")
run_command(get_context_command)
wait(5)


for l in range(1, NUM_ITERATIONS + 1):
    iteration_log = {
        "iteration": l,
        "timestamp": datetime.utcnow().isoformat(),
        "actions": {}
    }

    if l == 1:
        print(f"📨 Iteration {l}: Sending standard post...")
        duration, success, error = run_command([
            "cargo", "run", "--bin", "personas", "--release", "post",
            "-m", f"Message: {l}",
            "-g", GROUP_ID,
        ])
        iteration_log["actions"]["post"] = {"duration": duration, "success": success, "error": error if not success else None}
        wait(5)

    print(f"📨 Iteration {l}: Scanning...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "scan",
    ])
    iteration_log["actions"]["scan"] = {"duration": duration, "success": success, "error": error if not success else None}

    append_log(iteration_log)
    print(f"✅ Iteration {l} complete.")

    
wait(5)

# 2. Run normal post 100 times with rep
for j in range(1,  11): 
    iteration_log = {
        "iteration": j,
        "timestamp": datetime.utcnow().isoformat(),
        "actions": {}
    }

    wait(5)

    for k in range(1, 11):
        print(f"📨 Iteration {k}: Sending pseudo post...")
        duration, success, error = run_command([
            "cargo", "run", "--bin", "personas", "--release", "post-pseudo",
            "-m", f"Pseudonym Message: {k*j}",
            "-g", GROUP_ID,
            "-i", "2"
        ])
        iteration_log["actions"]["pseudonym_post"] = {"duration": duration, "success": success, "error": error if not success else None}
        wait(1)

        # Grab the message timestamp to increase rep
        ts_rep = get_latest_zkpair_timestamp()

        print(f"📨 Iteration {k}: Increasing reputation...")
        duration, success, error  = run_command([
            "cargo", "run", "--bin", "personas", "--release", "reaction",
            "-g", GROUP_ID,
            "-e", "👍",
            "-t", str(ts_rep)
        ])
        iteration_log["actions"]["reaction"] = {"duration": duration, "success": success, "error": error if not success else None}
        wait(1)
        
        print(f"📨 Iteration {k}: Counting reputation...")
        duration, success, error = run_command([
            "cargo", "run", "--bin", "personas", "--release", "rep",
        ])
        iteration_log["actions"]["rep"] = {"duration": duration, "success": success, "error": error if not success else None}
        wait(1)

    print(f"📨 Iteration {j}: Updating epoch...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "update-epoch",
    ])
    iteration_log["actions"]["update-epoch"] = {"duration": duration, "success": success, "error": error if not success else None}

    wait(1)

    append_log(iteration_log)
    print(f"✅ Iteration {j} complete.")


wait (4)

# 1. Run all other experiments 100 times
for i in range(1, NUM_ITERATIONS + 1):
    iteration_log = {
        "iteration": i,
        "timestamp": datetime.utcnow().isoformat(),
        "actions": {}
    }

    print(f"📨 Iteration {i}: Sending rate-limited pseudonym post...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "post-pseudo-rate",
        "-m", f"Rate Pseudo Message: {i}",
        "-g", GROUP_ID,
        "-c", THREAD,
        "-i", "1"
    ])
    iteration_log["actions"]["rate_pseudo_post"] = {"duration": duration, "success": success, "error": error if not success else None}
    wait(1)

    print(f"📨 Iteration {i}: Sending pseudonym post...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "post-pseudo",
        "-m", f"Pseudonym Message: {i}",
        "-g", GROUP_ID,
        "-i", "1"
    ])
    iteration_log["actions"]["pseudonym_post"] = {"duration": duration, "success": success, "error": error if not success else None}
    wait(1)


    print(f"📨 Iteration {i}: Proving badge...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "badge",
        "-i", "1",
        "-b", "0",
        "-g", GROUP_ID
    ])
    iteration_log["actions"]["badge"] = {"duration": duration, "success": success, "error": error if not success else None}
    wait(1)

    print(f"📨 Iteration {i}: Sending poll...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "poll",
        "-m", f"Poll Message: {i}",
        "-g", GROUP_ID
    ])
    iteration_log["actions"]["poll"] = {"duration": duration, "success": success, "error": error if not success else None}
    wait(1)

    # Grab the poll timestamp to vote on
    ts = get_latest_poll_timestamp()

    if ts:
        print(f"📨 Iteration {i}: Voting on poll {ts}...")
        duration, success, error = run_command([
            "cargo", "run", "--bin", "personas", "--release", "vote",
            "-g", GROUP_ID,
            "-t", str(ts),
            "-e", "👍"
        ])
        iteration_log["actions"]["vote"] = {"duration": duration, "success": success, "error": error if not success else None}
    else:
        iteration_log["actions"]["vote"] = {"duration": None, "success": False, "error": "No poll timestamp found"}

    wait(1)

    print(f"📨 Iteration {i}: Checking authorship...")
    duration, success, error = run_command([
        "cargo", "run", "--bin", "personas", "--release", "authorship",
        "-i", str(1),
        "-j", str(2),
        "-g", GROUP_ID
    ])
    iteration_log["actions"]["authorship"] = {"duration": duration, "success": success, "error": error if not success else None}

    wait(1)

    try:
        assert_all_timings_written()
    except RuntimeError as e:
        print(f"⚠️ Iteration {i} warning: {e}")
        iteration_log["timing_check_error"] = str(e)

    try:
        assert_all_timings_features_written()
    except RuntimeError as e:
        print(f"⚠️ Iteration {i} warning: {e}")
        iteration_log["timing_check_error"] = str(e)

    try:
        assert_all_timings_verify_written()
    except RuntimeError as e:
        print(f"⚠️ Iteration {i} warning: {e}")
        iteration_log["timing_check_error"] = str(e)

    get_timing_call_cb_log()

    get_timing_epoch_log()

    append_log(iteration_log)
    print(f"✅ Iteration {i} complete.")


# 4. Analyze results
# run_notebook("experiment_analysis.ipynb")