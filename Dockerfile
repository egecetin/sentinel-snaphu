FROM ubuntu:22.04
MAINTAINER egecetinn <egecetin@hotmail.com.tr>
CMD bash

# Configure timezone to avoid user input during build
ENV TZ=US/Pacific
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Copy required local files
COPY data/* /home/
COPY scripts/* /home/

# Install updates and dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    python3-dev \
    python3-pip \
    snaphu \
    wget \
    zip

RUN /usr/bin/python3 -m pip install --upgrade pip
RUN /usr/bin/python3 -m pip install -r /home/requirements.txt

# Install ESA SNAP
RUN /usr/bin/wget -q -O /home/esa-snap_all_unix_9_0.sh "http://step.esa.int/downloads/9.0/installers/esa-snap_all_unix_9_0_0.sh"
RUN bash /home/esa-snap_all_unix_9_0.sh -q -varfile /home/response.varfile
RUN /usr/bin/rm -f /home/esa-snap_all_unix_9_0.sh /home/response.varfile

# Reduce the image size
RUN apt-get autoremove -y
RUN apt-get clean -y
RUN rm -rf /src

ENTRYPOINT ["/usr/bin/python3", "/home/create_unwrap.py"]
