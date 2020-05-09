FROM alpine:latest

RUN apk update && apk upgrade
RUN apk add --update cutter tcpdump python py-pip bridge-utils iptables bash && \
    python -m pip install scapy && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*
	

COPY run.sh run.sh
COPY test.py test.py

ENTRYPOINT ["/run.sh"]
