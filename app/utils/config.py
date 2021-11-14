from typing import Union

from starlette.config import Config

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

config = Config('.env')
config_project = Config('.env_project')

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

PROJECT_NAME: str = config_project('PROJECT_NAME')
VERSION: str = config_project('VERSION')
ENV_MODE: str = config('ENV_MODE', default='KONS')

# NOTICE | SPAM | DEBUG | VERBOSE | INFO | NOTICE | WARNING | SUCCESS | ERROR | CRITICAL
LOGGING_LEVEL: str = config('LOGGING_LEVEL',  default='DEBUG')
LOGGING_VERBOSE: int = config('LOGGING_VERBOSE', cast=int,  default=0)
DEBUG: bool = True if LOGGING_LEVEL == 'DEBUG' or \
    LOGGING_LEVEL == 'VERBOSE' or LOGGING_LEVEL == 'SPAM' else False
DEBUG_RELOAD: bool = True if DEBUG else False

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


BASE_PATH: str = config('VM_BASE_PATH', default=f'.')

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

# It is required to do a free registration and create a license key
GEO_LICENSE_KEY: Union[str, None] = config('GEO_LICENSE_KEY',  default=None)
# docs: https://dev.maxmind.com/geoip/geoip2/geolite2/
GEO_LITE_TAR_FILE_URL = f'https://download.maxmind.com/app/geoip_download' \
                        f'?edition_id=GeoLite2-City' \
                        f'&license_key={GEO_LICENSE_KEY}' \
                        f'&suffix=tar.gz'
GEO_DB_FNAME = '/GeoLite2-City.mmdb'
GEO_DB_ZIP_FNAME = '/GeoIP2LiteCity.tar.gz'


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------

# Set your API keys here
SECRET_CENSYS_USERNAME: str = config('CENSYS_USERNAME', default=None)
SECRET_CENSYS_SECRET: str = config('CENSYS_SECRET', default=None)
SECRET_SHODAN_API_KEY: str = config('SHODAN_API_KEY', default=None)
SECRET_VIRUSTOTAL_API_KEY: str = config('VIRUSTOTAL_API_KEY', default=None)
SECRET_PASSIVE_TOTAL_USERNAME: str = config('PASSIVE_TOTAL_USERNAME', default=None)
SECRET_PASSIVE_TOTAL_KEY: str = config('PASSIVE_TOTAL_KEY', default=None)
SECRET_SECURITY_TRAILS_KEY: str = config('SECURITY_TRAILS_KEY', default=None)
SECRET_RIDDLER_EMAIL: str = config('RIDDLER_EMAIL', default=None)
SECRET_RIDDLER_PASSWORD: str = config('RIDDLER_PASSWORD', default=None)

SECRET_INSTAGRAM_SSID: str = config('INSTAGRAM_SSID', default=None)
