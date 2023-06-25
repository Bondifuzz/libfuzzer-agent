########################################
# Base image
########################################

FROM python:3.7-slim AS base
SHELL ["/bin/bash", "-c"]
ENV PYTHONUNBUFFERED=1
WORKDIR /fuzzer
USER root

RUN apt-get update
RUN apt-get install -y --no-install-recommends git

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements*.txt ./
RUN pip3 install -r requirements-prod.txt

########################################
# Release image
########################################

FROM python:3.7-slim
SHELL ["/bin/bash", "-c"]
ENV PYTHONUNBUFFERED=1
WORKDIR /fuzzer

ARG ENVIRONMENT=dev
ENV ENVIRONMENT=$ENVIRONMENT

COPY agent ./agent
COPY logging.yaml ./
COPY --from=base /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
CMD python3 -m agent
