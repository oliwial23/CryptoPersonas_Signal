#!/usr/bin/env bash
# Collect everything needed to diagnose a "Render process is gone / Exit Code: 9"
# crash into one file.
#
# Exit code 9 is SIGKILL: the process did not throw, it was killed. Electron reports
# only that fact, which is why the in-app error is the same regardless of cause. The
# evidence that DOES distinguish causes lives in three places this script gathers:
#
#   1. macOS crash reports (~/Library/Logs/DiagnosticReports). A jetsam/OOM kill is
#      recorded there with the process's memory footprint at death. This is the single
#      most decisive artifact and it is the one people never think to look at.
#   2. Signal's own logs, tailed around the kill.
#   3. The personas barrier anchor, whose age determines how much work every rebuild
#      does (see PERSONAS_DEMO.md §8.0).
#
# READ-ONLY: this script copies and reads. It deletes and modifies nothing.

set -uo pipefail

OUT="${1:-$HOME/personas-diagnostics.txt}"
ROSTER_DIR="${PERSONAS_ROSTER_DIR:-/tmp/personas-roster}"
SUPPORT="$HOME/Library/Application Support"

exec > >(tee "$OUT") 2>&1

echo "=============================================================="
echo "personas diagnostics — $(date)"
echo "=============================================================="
echo

echo "### machine ###"
sw_vers 2>/dev/null
echo "arch:      $(uname -m)"
echo "physical:  $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GB"
echo
echo "--- memory pressure (free pages vs. total) ---"
vm_stat 2>/dev/null | head -8
echo
echo "--- swap (a large 'used' means the machine was already under pressure) ---"
sysctl vm.swapusage 2>/dev/null
echo

echo "### TOP MEMORY CONSUMERS, whatever they are ###"
# Deliberately NOT filtered to Signal. Under macOS memory pressure the jetsam killer
# targets whoever is convenient, so the process that DIES is often not the process
# responsible. The first version of this script only listed Signal processes and
# therefore could not have found the real cause.
ps -Ao rss,pid,comm -m 2>/dev/null | head -16 | awk '
  NR==1 { print "     RSS  PID      COMMAND"; next }
  { rss=$1/1024; printf "%8.0f MB  %-8s %s\n", rss, $2, substr($0, index($0,$3)) }' |
  cut -c1-140
echo

echo "### Signal/Electron processes specifically ###"
ps -Ao rss,pid,command 2>/dev/null | grep -i "[S]ignal" | awk '
  { rss=$1/1024; printf "%8.0f MB  pid %-8s %s\n", rss, $2, substr($0, index($0,$3)) }' |
  cut -c1-160 | head -20
echo

echo "### MEMORY PRESSURE VERDICT ###"
# The decisive check. A renderer SIGKILL with no crash report and no application error
# is what a jetsam (out-of-memory) kill looks like from inside Electron.
python3 - <<'PY' 2>/dev/null || echo "(python3 unavailable)"
import subprocess, re
def sysctl(k):
    try: return subprocess.check_output(["sysctl","-n",k],text=True).strip()
    except Exception: return ""
vm = subprocess.check_output(["vm_stat"],text=True)
page = int(re.search(r"page size of (\d+)", vm).group(1))
def pages(label):
    m = re.search(rf"{label}:\s+(\d+)", vm)
    return int(m.group(1)) if m else 0
free_gb = pages("Pages free") * page / 1024**3
swap = sysctl("vm.swapusage")
m = re.search(r"total = ([\d.]+)M.*used = ([\d.]+)M", swap)
print(f"free RAM: {free_gb:.2f} GB")
if m:
    total, used = float(m.group(1)), float(m.group(2))
    pct = 100 * used / total if total else 0
    print(f"swap:     {used/1024:.1f} GB used of {total/1024:.1f} GB ({pct:.0f}% full)")
    if pct > 75 or free_gb < 3:
        print()
        print("VERDICT: THE MACHINE IS OUT OF MEMORY.")
        print("  A renderer killed with exit code 9 and no crash report is macOS's")
        print("  jetsam reclaiming memory. This is environmental — no code change in")
        print("  this repo will fix it. Quit the top consumers above, or reboot.")
    else:
        print("\nVERDICT: memory looks healthy; the kill is probably not jetsam.")
PY
echo

echo "### macOS crash reports for the renderer (MOST IMPORTANT) ###"
DIAG="$HOME/Library/Logs/DiagnosticReports"
if [[ -d "$DIAG" ]]; then
  reports="$(find "$DIAG" -maxdepth 1 -type f \
    \( -name '*Signal*' -o -name '*Electron*' \) -mtime -3 2>/dev/null | sort | tail -5)"
  if [[ -n "$reports" ]]; then
    while read -r r; do
      [[ -z "$r" ]] && continue
      echo "----------------------------------------------------------"
      echo "REPORT: $r"
      echo "----------------------------------------------------------"
      # The header carries the kill reason; for a jetsam kill it names the memory
      # limit and the footprint that exceeded it.
      head -40 "$r"
      echo "  ... [truncated] ..."
      grep -iE "jetsam|memory|footprint|termination|OOM|resource" "$r" 2>/dev/null | head -20
      echo
    done <<< "$reports"
  else
    echo "No Signal/Electron crash reports in the last 3 days."
    echo
    echo "NOTE: a jetsam (memory) kill is sometimes logged only here instead:"
    log show --last 2h --predicate 'senderImagePath CONTAINS "Jetsam" OR eventMessage CONTAINS "jetsam"' \
      2>/dev/null | grep -i signal | tail -20 ||
      echo "  (log show returned nothing)"
  fi
else
  echo "No $DIAG directory."
fi
echo

echo "### personas barrier anchor ###"
HB="$ROSTER_DIR/personas-heartbeat.json"
if [[ -f "$HB" ]]; then
  echo "file:    $HB"
  cat "$HB"
  anchor="$(python3 -c "import json,sys;print(json.load(open('$HB'))['anchorMs'])" 2>/dev/null || echo "")"
  period="$(python3 -c "import json,sys;print(json.load(open('$HB'))['periodMs'])" 2>/dev/null || echo "")"
  if [[ -n "$anchor" && -n "$period" ]]; then
    python3 - <<PY
now = __import__('time').time() * 1000
anchor, period = $anchor, $period
b = int((now - anchor) / period)
age_h = (now - anchor) / 3_600_000
print(f"\nanchor age:      {age_h:.1f} hours")
print(f"current barrier: {b}")
print("rebuild() loops 0..=barrier on EVERY crossing, so this is the per-rebuild cost.")
print("VERDICT:", "FINE" if b < 2000 else "TOO HIGH — this alone can SIGKILL the renderer")
PY
  fi
else
  echo "No heartbeat file at $HB (fresh anchor will be minted on next start — good)."
fi
echo

echo "### proving keys ###"
KEYS="${PERSONAS_KEYS_DIR:-$HOME/.personas-demo-keys}"
[[ -d "$KEYS" ]] && du -sh "$KEYS" 2>/dev/null || echo "No keys dir at $KEYS"
echo

echo "### Signal logs, per instance ###"
for d in "$SUPPORT"/Signal-*; do
  [[ -d "$d" ]] || continue
  echo "=========================================================="
  echo "INSTANCE: $(basename "$d")"
  echo "=========================================================="
  logdir="$d/logs"
  if [[ -d "$logdir" ]]; then
    # Any file, not just *.log — Signal rotates to extensionless and .log.gz names, and
    # the first version of this script matched only '*.log' and so reported "no .log
    # files" for instances whose logs were sitting right there.
    newest="$(find "$logdir" -type f 2>/dev/null |
              xargs ls -t 2>/dev/null | head -1)"
    if [[ -n "$newest" ]]; then
      echo "--- personas lines (engine, barrier, scan) ---"
      grep -iE "personas|barrier|scan|reputation" "$newest" 2>/dev/null | tail -40
      echo
      echo "--- last 60 lines before the end of the log ---"
      tail -60 "$newest"
    else
      echo "(no .log files)"
    fi
  else
    echo "(no logs dir)"
  fi
  echo
done

echo "=============================================================="
echo "Written to: $OUT"
echo "=============================================================="
