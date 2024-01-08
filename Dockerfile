FROM alpine:3.18
LABEL maintainer="th@telephant.eu"
RUN apk add --update --no-cache python3 poetry
RUN mkdir /ts
RUN mkdir /data
COPY . /ts
WORKDIR /ts
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev --no-interaction --no-ansi
ENV TELEPHANT_SERVER_CONFIG=/data/server-config.yaml
ENTRYPOINT ["/usr/bin/telephant_server"] 
