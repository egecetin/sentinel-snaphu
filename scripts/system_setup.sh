#!/bin/bash

sudo apt-get update && sudo apt-get install -y \
    libgfortran5 \
    python3-dev \
    python3-pip \
    snaphu \
    wget \
    zip

python3 -m pip install --upgrade pip
python3 -m pip install -r ../data/requirements.txt

wget -O esa-snap_sentinel_unix_9_0.sh "http://step.esa.int/downloads/9.0/installers/esa-snap_sentinel_unix_9_0_0.sh"
sudo bash esa-snap_sentinel_unix_9_0.sh -q -varfile ../data/response.varfile
rm esa-snap_sentinel_unix_9_0.sh

ssh-keygen -t rsa -b 4096

snap --nosplash --nogui --modules --update-all 2>&1 | while read -r line; do
    echo "$line"
    [ "$line" = "updates=0" ] && sleep 2 && pkill -TERM -f "snap/jre/bin/java"
done
