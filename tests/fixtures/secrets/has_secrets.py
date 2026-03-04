# This file intentionally contains fake secrets for testing

AWS_ACCESS_KEY = "AKIAIOSFODNN7RSTUVWX"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYZAB1234CDEF"

# GitHub token
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"

# Slack token (uses xoxs- prefix to avoid push protection on xoxb-)
slack_token = "xoxs-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"

# Database connection
db_url = "postgres://admin:supersecretpassword@db.notreal.internal:5432/mydb"

# Private key
pem_data = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/yGxPjLwGSP7dBqn1vKRH
-----END RSA PRIVATE KEY-----"""

# Generic password
config = {
    "password": "MyS3cureP@ssw0rd!",
}

# API key (uses sk_test_ to avoid push protection on sk_live_)
api_key = "sk_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456"
