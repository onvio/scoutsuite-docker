FROM python:3.8.6-slim-buster

RUN pip install ScoutSuite
ADD scan.py /opt/

WORKDIR /opt/
VOLUME /var/reports

ENTRYPOINT [ "python", "/opt/scan.py" ]