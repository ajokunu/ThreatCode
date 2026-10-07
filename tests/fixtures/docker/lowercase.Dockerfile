# Lowercase instructions are legal: BuildKit matches keywords case-insensitively.
from ubuntu:22.04

arg api_token=ghp_0123456789abcdef0123456789abcdef0123
env db_password=hunter2 app_port=8080

run apt-get update && apt-get install -y curl
run curl -fsSL https://get.example.com/install.sh | sh

copy server.key /etc/ssl/private/
expose 8080
user root

cmd ["/usr/local/bin/app"]
