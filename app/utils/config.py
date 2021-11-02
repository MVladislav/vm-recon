import logging
import sys
from pathlib import Path

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

try:
    from starlette.config import Config
except ImportError:
    source_to_install = 'starlette'
    logging.log(logging.CRITICAL, f'Failed to Import {source_to_install}')
    try:
        # choice = input(f'[*] Attempt to Auto-istall {source_to_install}? [y/N]')
        choice = 'y'
    except KeyboardInterrupt:
        logging.log(logging.INFO, 'User Interrupted Choice')
        sys.exit(1)
    if choice.strip().lower()[0] == 'y':
        logging.log(logging.INFO, f'Attempting to Install {source_to_install}')
        sys.stdout.flush()
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", source_to_install])
            from starlette.config import Config
            logging.log(logging.INFO, '[DONE]')
        except Exception:
            logging.log(logging.CRITICAL, '[FAIL]')
            sys.exit(1)
    elif choice.strip().lower()[0] == 'n':
        logging.log(logging.INFO, 'User Denied Auto-install')
        sys.exit(1)
    else:
        logging.log(logging.WARNING, 'Invalid Decision')
        sys.exit(1)


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

config = Config('.env')

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


LICENSE: str = config('LICENSE', default='GNU AGPLv3')
AUTHOR: str = config('AUTHOR', default='MVladislav')
AUTHOR_EMAIL: str = config('AUTHOR_EMAIL', default='info@mvladislav.online')

PROJECT_NAME: str = config('PROJECT_NAME', default='vm_recon')
ENV_MODE: str = config('ENV_MODE', default='KONS')
VERSION: str = config('VERSION', default='0.0.1')

# NOTICE | SPAM | DEBUG | VERBOSE | INFO | NOTICE | WARNING | SUCCESS | ERROR | CRITICAL
LOGGING_LEVEL: str = config('LOGGING_LEVEL',  default='DEBUG')
LOGGING_VERBOSE: int = config('LOGGING_VERBOSE', cast=int,  default=2)
DEBUG: bool = True if LOGGING_LEVEL == 'DEBUG' or \
    LOGGING_LEVEL == 'VERBOSE' or LOGGING_LEVEL == 'SPAM' else False
DEBUG_RELOAD: bool = True if DEBUG else False

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


BASE_PATH: str = config('VM_BASE_PATH', default=f'{Path.home()}/Documents/{PROJECT_NAME}')


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

# Set your API keys here
SUBFINDER_CENSYS_USERNAME: str = config('CENSYS_USERNAME', default='<API-KEY-HERE>')
SUBFINDER_CENSYS_SECRET: str = config('CENSYS_SECRET', default='<API-KEY-HERE>')
SUBFINDER_SHODAN_API_KEY: str = config('SHODAN_API_KEY', default='<API-KEY-HERE>')
SUBFINDER_VIRUSTOTAL_API_KEY: str = config('VIRUSTOTAL_API_KEY', default='<API-KEY-HERE>')
SUBFINDER_PASSIVE_TOTAL_USERNAME: str = config('PASSIVE_TOTAL_USERNAME', default='<API-KEY-HERE>')
SUBFINDER_PASSIVE_TOTAL_KEY: str = config('PASSIVE_TOTAL_KEY', default='<API-KEY-HERE>')
SUBFINDER_SECURITY_TRAILS_KEY: str = config('SECURITY_TRAILS_KEY', default='<API-KEY-HERE>')
SUBFINDER_RIDDLER_EMAIL: str = config('RIDDLER_EMAIL', default='<API-KEY-HERE>')
SUBFINDER_RIDDLER_PASSWORD: str = config('RIDDLER_PASSWORD', default='<API-KEY-HERE>')

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

# It is required to do a free registration and create a license key
GEO_LICENSE_KEY: str = config('GEO_LICENSE_KEY',  default=None)
# docs: https://dev.maxmind.com/geoip/geoip2/geolite2/
GEO_LITE_TAR_FILE_URL = f'https://download.maxmind.com/app/geoip_download' \
                        f'?edition_id=GeoLite2-City' \
                        f'&license_key={GEO_LICENSE_KEY}' \
                        f'&suffix=tar.gz'
GEO_DB_FNAME = '/GeoLite2-City.mmdb'
GEO_DB_ZIP_FNAME = '/GeoIP2LiteCity.tar.gz'
