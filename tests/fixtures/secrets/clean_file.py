# This file has no secrets

import os

DATABASE_URL = "${DB_URL}"  # Template variable
API_KEY = "<YOUR_API_KEY>"  # Placeholder
PASSWORD = "changeme"  # Test/example value

real_key = os.environ.get("API_KEY", "")
