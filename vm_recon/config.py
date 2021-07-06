import os
from pathlib import Path

PROJECT = "vm_recon"
VERSION = '0.0.1'
VERBOSE = os.environ.get('VM_VERBOSE', 0)

PROJECT_NAME = "default"
BASE_PATH = os.environ.get('VM_BASE_PATH', f'{Path.home()}/Documents/vm-hacking')


# Set your API keys here
SUBFINDER_VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '<API-KEY-HERE>')
SUBFINDER_PASSIVE_TOTAL_USERNAME = os.environ.get('PASSIVE_TOTAL_USERNAME', '<API-KEY-HERE>')
SUBFINDER_PASSIVE_TOTAL_KEY = os.environ.get('PASSIVE_TOTAL_KEY', '<API-KEY-HERE>')
SUBFINDER_SECURITY_TRAILS_KEY = os.environ.get('SECURITY_TRAILS_KEY', '<API-KEY-HERE>')
SUBFINDER_RIDDLER_EMAIL = os.environ.get('RIDDLER_EMAIL', '<API-KEY-HERE>')
SUBFINDER_RIDDLER_PASSWORD = os.environ.get('RIDDLER_PASSWORD', '<API-KEY-HERE>')
SUBFINDER_CENSYS_USERNAME = os.environ.get('CENSYS_USERNAME', '<API-KEY-HERE>')
SUBFINDER_CENSYS_SECRET = os.environ.get('CENSYS_SECRET', '<API-KEY-HERE>')
SUBFINDER_SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '<API-KEY-HERE>')
