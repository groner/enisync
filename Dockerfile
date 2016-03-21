FROM python:3.5-alpine

RUN pip install pyroute2
COPY enisync.py /

ENTRYPOINT ["/usr/local/bin/python3", "-u", "/enisync.py"]
