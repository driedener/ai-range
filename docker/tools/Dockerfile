FROM python:3.12-slim

ARG TERRAFORM_VERSION=1.9.8
ARG PACKER_VERSION=1.11.2

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip git openssh-client sshpass ca-certificates xorriso jq \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/tf.zip https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip \
 && unzip -oq /tmp/tf.zip terraform -d /usr/local/bin && rm /tmp/tf.zip \
 && curl -fsSL -o /tmp/packer.zip https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip \
 && unzip -oq /tmp/packer.zip packer -d /usr/local/bin && rm /tmp/packer.zip

RUN pip install --no-cache-dir ansible-core==2.17.5 pywinrm==0.5.0 websocket-client==1.8.0 pycryptodome==3.21.0

COPY requirements.yml /tmp/requirements.yml
RUN ansible-galaxy collection install -r /tmp/requirements.yml

WORKDIR /work
