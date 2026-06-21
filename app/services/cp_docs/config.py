import os

# API Configuration
API_CONFIGS = {
    'management': {
        'name': 'Management API',
        'base_url': 'https://sc1.checkpoint.com/documents/latest/APIs/',
        'default_server': 'https://<mgmt-server>:<port>/web_api',
        'fallback_version': 'v2.0.1'
    },
    'gaia': {
        'name': 'GAiA API',
        'base_url': 'https://sc1.checkpoint.com/documents/latest/GaiaAPIs/',
        'default_server': 'https://<gaia-server>:<port>/gaia_api',
        'fallback_version': 'v1.8'
    }
}

# Environment variables for server URLs
CHECKPOINT_SERVER_URL = os.getenv("CHECKPOINT_SERVER_URL", API_CONFIGS['management']['default_server'])
GAIA_SERVER_URL = os.getenv("GAIA_SERVER_URL", API_CONFIGS['gaia']['default_server'])
# TLS verification is ON by default (org policy: never disable TLS). The CP doc CDN
# (sc1.checkpoint.com) presents a valid public certificate, so verification succeeds.
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
CHECKPOINT_API_VERSION = os.getenv("CHECKPOINT_API_VERSION", None)

# Control visibility of undocumented/unpublished API calls
SHOW_UNDOCUMENTED = os.getenv("SHOW_UNDOCUMENTED", "false").lower() == "true"
