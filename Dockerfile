FROM python:3.11-slim

# Install tshark (faster pcap parsing) and gcc for Cython compilation
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        tshark \
        gcc \
        python3-dev \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-compile the Cython extension
RUN python setup.py build_ext --inplace

# Default configuration — override any of these with -e or docker-compose environment:
#   KITSUNE_IFACE   network interface to sniff      (default: eth0)
#   KITSUNE_WS_PORT WebSocket port                  (default: 8765)
#   KITSUNE_FM_GRACE feature-mapping grace packets  (default: 5000)
#   KITSUNE_AD_GRACE anomaly-detector grace packets (default: 50000)
#   KITSUNE_MAX_AE  max features per autoencoder    (default: 10)
ENV KITSUNE_IFACE=eth0
ENV KITSUNE_WS_PORT=8765
ENV KITSUNE_FM_GRACE=5000
ENV KITSUNE_AD_GRACE=50000
ENV KITSUNE_MAX_AE=10

EXPOSE 8765

# Live capture requires CAP_NET_RAW + CAP_NET_ADMIN:
#   docker run --cap-add NET_RAW --cap-add NET_ADMIN ...
#
# To sniff a Docker bridge (e.g. docker0 or br-<id>):
#   docker run --cap-add NET_RAW --cap-add NET_ADMIN --network host \
#              -e KITSUNE_IFACE=docker0 -p 8765:8765 kitsune-py
#
# To sniff only traffic on a specific compose network, attach the container
# to that network and set KITSUNE_IFACE to the bridge interface name.

CMD ["python", "monitor.py"]
