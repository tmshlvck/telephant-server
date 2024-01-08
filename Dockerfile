FROM alpine:3.18
LABEL maintainer="th@telephant.eu"
RUN apk add --update --no-cache python3 poetry
RUN mkdir /ts
RUN mkdir /data
COPY . /ts
WORKDIR /ts
RUN poetry install
ENV TELEPHANT_SERVER_CONFIG=/data/server-config.yaml;
ENTRYPOINT ["telephant-server"]
