# pull official base image
FROM python:3.10-slim

# RUN apt-get update && apt-get install -y build-essential gcc gdal-bin libgdal-dev default-libmysqlclient-dev
RUN apt-get update && apt-get install -y build-essential gcc postgis postgresql-client libpq-dev

# set work directory
WORKDIR /code

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip

# copy project
# RUN pip install gunicorn
COPY . /code/

RUN pip install -r requirements.txt
RUN pip install gunicorn