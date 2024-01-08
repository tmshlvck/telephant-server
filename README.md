# Telephant Server

This is the server (API + Web interface) component of Telephant.

## Development and testing

Run Telephant server on localhost with no HTTPS proxy:

```
export TELEPHANT_SERVER_CONFIG=test/server-config.yaml; poetry run telephant_server
```

Build and deploy Docker/Podman container"

```
podman build -t telephant_server:0.1 .
```

Starting Dockerized app and create systemd service for that:

```
mkdir /srv/telephant_server/
mkdir /srv/telephant_server/reports/
cp server-config.yaml /srv/telephant_server/
vi /srv/telephant_server/server-config.yaml

sudo podman run --privileged --network=host --name telephant_server -d -v /srv/telephant_server:/data telephant_server
sudo podman run --privileged --network=host --name telephant_server -d -v /srv/telephant_server:/data telephant_server
sudo podman generate systemd --new --files --name telephant_server
sudo mv container-telephant_server.service /etc/systemd/system/
sudo systemctl enable container-telephant_server
```
