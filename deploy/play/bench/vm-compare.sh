#!/usr/bin/env bash
# Measure both implementations on this VM, on the same hardware, into bench/results/.
# Run from anywhere, after building the image and starting the validator (README.md).
#
#   ./bench/vm-compare.sh quick    # about an hour: everything except the long history
#   ./bench/vm-compare.sh long     # hours: serverless at 1000 records of history
#
# Proving uses every core, so /play is sluggish for testers while this runs. Keep it
# running past a logout with:
#
#   nohup ./bench/vm-compare.sh long > ~/vm-compare-long.log 2>&1 &
set -euo pipefail
cd "$(dirname "$0")/.."

DAY="$(date +%F)"
OPS="join,anon_post,pseudo_post,vote,rating,scan,moderation"
bench() { docker compose run --rm bench "$@"; }

serverless() {
  bench --keys /shared/keys --history "$1" --iters 20 --warmup 3 --only "$OPS" \
    --skip-constraints --label "VM, serverless" \
    --out "/results/$DAY-vm-serverless-h$1.json"
}
server() {
  bench --server --server-dir /tmp/server-bench --history "$1" --iters 20 --warmup 3 \
    --callbacks 16 --label "VM, server-based" \
    --out "/results/$DAY-vm-server-h$1.json"
}

case "${1:-}" in
  quick)
    server 0
    server 1000
    # Capacity, without the gateway or the load balancer in the way.
    bench --server --load --server-url http://validator:3000/ --label "VM, server-based" \
      --out "/results/$DAY-vm-load.json"
    serverless 0
    serverless 150
    ;;
  long)
    serverless 1000
    ;;
  *)
    echo "usage: $0 quick|long" >&2
    exit 2
    ;;
esac
echo "done; results are in $(pwd)/bench/results/"
