#!/bin/bash

n=4
t=1

cargo build --release
for i in {0..$n}
do
  echo "Starting node $i"
  cargo run --bin rand-beacon &
  # ./node
done

# can pass in num_node and threshold here or we manually run this outside of this file
# stdin on nodes needs to be closed before we do this
cargo run --bin cm $n $t
# OR ./cm $n $t


#get PID of running nodes
ps -ef | grep rand-beacon | awk '{print $2}'


# kill all running nodes and the config manager
ps -ef | grep rand-beacon | grep -v grep | awk '{print $2}' | xargs kill
ps -ef | grep cm | grep -v grep | awk '{print $2}' | xargs kill 