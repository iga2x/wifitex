FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV HASHCAT_VERSION=hashcat-6.2.6
ENV AIRCRACK_VERSION=1.7.4

# Install system dependencies in one layer
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    ca-certificates \
    gcc \
    openssl \
    make \
    kmod \
    nano \
    wget \
    p7zip \
    build-essential \
    libsqlite3-dev \
    libpcap0.8-dev \
    libpcap-dev \
    sqlite3 \
    pkg-config \
    libnl-genl-3-dev \
    libssl-dev \
    net-tools \
    iw \
    ethtool \
    usbutils \
    pciutils \
    wireless-tools \
    git \
    curl \
    unzip \
    macchanger \
    tshark \
    python3-dev \
    python3-pip \
    python3-pyqt6 \
    python3-pyqt6.qtwidgets \
    python3-pyqt6.qtcore \
    python3-pyqt6.qtgui \
    && apt-get build-dep aircrack-ng -y \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir \
    psutil \
    requests \
    netifaces \
    watchdog \
    qdarkstyle \
    qtawesome

# Install Aircrack-ng (latest version)
WORKDIR /tmp
RUN wget https://download.aircrack-ng.org/aircrack-ng-${AIRCRACK_VERSION}.tar.gz && \
    tar xzf aircrack-ng-${AIRCRACK_VERSION}.tar.gz && \
    cd aircrack-ng-${AIRCRACK_VERSION} && \
    make && \
    make install && \
    airodump-ng-oui-update && \
    cd / && rm -rf /tmp/aircrack-ng-*

# Install hashcat (latest version)
WORKDIR /tmp
RUN mkdir hashcat && \
    cd hashcat && \
    wget https://hashcat.net/files_legacy/${HASHCAT_VERSION}.7z && \
    7zr e ${HASHCAT_VERSION}.7z && \
    ln -s /tmp/hashcat/hashcat-cli64.bin /usr/bin/hashcat && \
    cd / && rm -rf /tmp/hashcat

# Install other tools
WORKDIR /tmp
RUN git clone https://github.com/wiire/pixiewps && \
    cd pixiewps && \
    make && \
    make install && \
    cd / && rm -rf /tmp/pixiewps

RUN git clone https://github.com/aanarchyy/bully && \
    cd bully/src && \
    make && \
    make install && \
    cd / && rm -rf /tmp/bully

RUN git clone https://github.com/gabrielrcouto/reaver-wps.git && \
    cd reaver-wps/src && \
    ./configure && \
    make && \
    make install && \
    cd / && rm -rf /tmp/reaver-wps

RUN git clone https://github.com/roobixx/cowpatty.git && \
    cd cowpatty && \
    make && \
    cd / && rm -rf /tmp/cowpatty

# Install wifitex (copy local files instead of cloning)
WORKDIR /app
COPY . /app/wifitex/
WORKDIR /app/wifitex

# Install wifitex package
RUN pip3 install -e .

# Set working directory
WORKDIR /app/wifitex

# Set entry point
ENTRYPOINT ["/bin/bash"]