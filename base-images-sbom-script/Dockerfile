FROM registry.access.redhat.com/ubi9/python-39:1-186.1719562233@sha256:c949cb81a6f72ca157501949d07095e87b3c8f1a9ff5a69ff0a858faac21217b

WORKDIR /app
COPY app/requirements.txt  /app
COPY app/base_images_sbom_script.py /app

RUN pip3 install -r requirements.txt
