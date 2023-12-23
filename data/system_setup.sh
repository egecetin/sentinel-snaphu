#!/bin/bash

sudo apt-get update && apt-get install -y \
    python3-dev \
    python3-pip \
    snaphu \
    wget \
    zip

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

wget -q -O esa-snap_all_unix_9_0.sh "http://step.esa.int/downloads/9.0/installers/esa-snap_all_unix_9_0_0.sh"
bash esa-snap_all_unix_9_0.sh -q -varfile response.varfile
rm esa-snap_all_unix_9_0.sh
