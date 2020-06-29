FROM python:3.6.10-slim-buster@sha256:cf53095d28a6c1af7636357a4f1c87d56fd30a86694ab9c028737d2150eb331e

RUN pip3 install -r .requirement.txt
