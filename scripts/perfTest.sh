#!/bin/bash

NETWORK_NAME=jasdeepLocal

LOCAL_HOST_IP=192.168.56.101
LOCAL_HOST_TINC_IP=192.168.57.1

REMOTE_HOST_IP=192.168.56.102
REMOTE_HOST_USER=jasdeep
REMOTE_HOST_PASSWORD=golfing

REMOTE_HOST_TINC_IP=192.168.57.2

function remote_host_command {
(
    /usr/bin/expect << EOD
    spawn ssh -t $REMOTE_HOST_USER@$REMOTE_HOST_IP "$1"
    expect -nocase "password:"
    send "$REMOTE_HOST_PASSWORD\r"
    expect eof
EOD
)
}

# Checkout code for generating flame graph
if [ ! -d "FlameGraph" ]; then
    git clone https://github.com/brendangregg/FlameGraph.git
fi

# Names for output files for this run
TIMESTAMP=`date +%s`
TINCD_PERF_FILE="tinc_perf-$TIMESTAMP.dat"
TINCD_STRACE_FILE="tinc_strace-$TIMESTAMP.txt"
NETPERF_PERF_FILE="netperf_perf-$TIMESTAMP.dat"
NETPERF_TINC_PERF_FILE="netperf_through_tinc_perf-$TIMESTAMP.dat"
SYSTEM_PERF_FILE="sys_perf-$TIMESTAMP.dat"
SYSTEM_PERF_W_TINC_FILE="sys_perf_w_tinc-$TIMESTAMP.dat"
PWD=`pwd`
HOST_IFACE_LOG="$PWD/host_bandwidth-$TIMESTAMP.txt"
TINC_IFACE_LOG="$PWD/tinc_bandwidth-$TIMESTAMP.txt"

# Start tincd on this host and get its process id
sudo tincd --debug=0 -n $NETWORK_NAME
LOCAL_TINCD_PID=`pgrep tincd`
# Start tincd on the remote host
remote_host_command "sudo tincd --debug=0 -n $NETWORK_NAME" > /dev/null
# Start netperf server on remote host
remote_host_command "nohup netserver" > /dev/null

echo "Testing bulk data performance w/o tinc VPN"
LOCAL_HOST_INTERFACE=`sudo ifconfig | grep -B 1 $LOCAL_HOST_IP | head -n 1 | cut -d ' ' -f 1`
sudo ifstat -i $LOCAL_HOST_INTERFACE -n 0.1 > $HOST_IFACE_LOG &
sudo perf record -a -g -o $SYSTEM_PERF_FILE &
#sudo perf record  -g -o $NETPERF_PERF_FILE -- netperf -H $REMOTE_HOST_IP
#sudo perf stat -a netperf -H $REMOTE_HOST_IP
netperf -H $REMOTE_HOST_IP
sudo pkill -2 perf
sleep 25
sudo pkill -3 perf
sudo pkill -3 ifstat

echo "Testing bulk data performance w/ tinc VPN"
#sudo perf record  -g -o $TINCD_PERF_FILE -p $LOCAL_TINCD_PID &
#sudo strace -c -p $LOCAL_TINCD_PID -o $TINCD_STRACE_FILE &
LOCAL_TINC_INTERFACE=`sudo ifconfig | grep -B 1 $LOCAL_HOST_TINC_IP | head -n 1 | cut -d ' ' -f 1`
sudo ifstat -i $LOCAL_TINC_INTERFACE -n 0.1 > $TINC_IFACE_LOG &
sudo perf record -a -g -o $SYSTEM_PERF_W_TINC_FILE &
#sudo perf record -g -o $NETPERF_TINC_PERF_FILE -- netperf -H $REMOTE_HOST_TINC_IP
#sudo perf stat -a netperf -H $REMOTE_HOST_TINC_IP
netperf -H $REMOTE_HOST_TINC_IP
sudo pkill -2 perf
sleep 25
sudo pkill -3 perf
sudo pkill -3 ifstat
sudo pkill -3 strace
sudo pkill -3 tincd

# Shut down netserver on remote host
remote_host_command "sudo pkill -3 netserver" > /dev/null
# Shut down tincd on remote host
remote_host_command "sudo pkill -3 tincd" > /dev/null

# Generate flame graphs
FLAME_GRAPH="perf-$TIMESTAMP.svg"
FLAME_GRAPH_TINC="perf-tinc-$TIMESTAMP.svg"
sudo perf script -i $SYSTEM_PERF_FILE | sudo ./FlameGraph/stackcollapse-perf.pl | sudo ./FlameGraph/flamegraph.pl > $FLAME_GRAPH
sudo perf script -i $SYSTEM_PERF_W_TINC_FILE | sudo ./FlameGraph/stackcollapse-perf.pl | sudo ./FlameGraph/flamegraph.pl > $FLAME_GRAPH_TINC
