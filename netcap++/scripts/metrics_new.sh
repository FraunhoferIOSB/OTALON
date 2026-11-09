#!/bin/bash
# Runs network-monitor and collects telemetry data in a configurable interval.
# The output will be written to a csv file.

OUTFILE="$(date +%Y%m%d%H%M%S)-metrics.csv"
INTERVAL=10

CMD="watch"
#CMD="./build/src/network-capture"
CMD_ARGS="ls -lah"
#CMD_ARGS="--input-iface net_igc --output-file out.csv"

# Parses the output to collect metrics. The first line is the main thread. For
# the child threads, only the pid and CPU usage is added.
read -d '' AWK_PROG << 'EOF'
{
    if (NR == 8) {
        printf "%d;%f;%f", $1, $9, $10
    } else if (NR > 8) {
        printf ";%d:%f", $1, $10
    }
}

END {
    printf "\\n"
}
EOF

# Trap handler for Ctrl-C.
trap_handler () {
    echo "Killing process and worker." >&2
    kill -KILL ${process}
    kill -KILL ${worker}
    echo "Exiting." >&2
}

# Collect telemetry data and format it as a CSV line.
collect_metrics () {
    echo "Timestamp,PID,MEM,CPU" > ${OUTFILE}
    while true; do
        metrics=$(top -b -n 1 -p ${1} | awk "${AWK_PROG}")
        printf "%s;%s\n" $(date +"%s") ${metrics} >> ${OUTFILE}
        sleep ${INTERVAL}
    done
}

# Start the network-monitor process as root and get its PID.
#sudo $CMD $CMD_ARGS &
process=$1

# Start the telemetry collector.
collect_metrics 374023 &
worker=$!

# Handle Ctrl-C.
trap trap_handler SIGINT SIGTERM

wait ${process}
kill -KILL ${process}
kill ${worker}
