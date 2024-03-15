FROM registry.access.redhat.com/ubi9/python-39:1-165@sha256:4da8ddb12096a31d8d50e58ea479ba2fe2f252f215fbaf5bf90923a1827463ba

WORKDIR /app
COPY app/requirements.txt  /app
COPY app/base_images_sbom_script.py /app

RUN pip3 install -r requirements.txt
