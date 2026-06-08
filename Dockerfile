FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash-completion \
    gcc \
    libc6-dev \
    libpcap-dev \
    make \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN echo '. /etc/bash_completion' >> /root/.bashrc

WORKDIR /app
COPY . .

RUN make re

ENTRYPOINT ["./ft_nmap"]
