import logging
from pathlib import Path
from typing import List, Union

import verboselogs
from starlette.config import Config
from stringcolor.ops import Bold


class Settings():
    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    config = Config(".env")
    config_project = Config(".env_project")
    # --------------------------------------------------------------------------
    #
    # LOGGING CONFIG
    #
    # --------------------------------------------------------------------------
    PROJECT_NAME: str = config_project("PROJECT_NAME", default="vm_recon")
    VERSION: str = config_project("VERSION", default="0.0.3")
    # KONS | PROD
    ENV_MODE: str = config("ENV_MODE", default="KONS")
    TIME_ZONE: str = config("TIME_ZONE", default="Europe/Berlin")
    # CRITICAL | ERROR | SUCCESS | WARNING | NOTICE | INFO | VERBOSE | DEBUG | SPAM | NOTSET
    LOGGING_LEVEL: str = config("LOGGING_LEVEL", default="DEBUG")
    # 0-4
    LOGGING_VERBOSE: int = config("LOGGING_VERBOSE", cast=int, default=0)
    DEBUG: bool = True if LOGGING_LEVEL == "DEBUG" or LOGGING_LEVEL == "VERBOSE" or LOGGING_LEVEL == "SPAM" else False
    DEBUG_RELOAD: bool = True if DEBUG else False
    # --------------------------------------------------------------------------
    #
    # BASE CONFIG
    #
    # --------------------------------------------------------------------------
    BASE_PATH: str = config("VM_BASE_PATH", default=".")
    HOME_PATH: str = config("VM_HOME_PATH", default=str(Path.home()))
    USE_SUDO: List[str] = [config("USE_SUDO", default="")]
    DISABLE_SPLIT_PROJECT: bool = config(
        "DISABLE_SPLIT_PROJECT", cast=bool, default=False
    )
    DISABLE_SPLIT_HOST: bool = config("DISABLE_SPLIT_HOST", cast=bool, default=False)
    PRINT_ONLY_MODE: bool = config("PRINT_ONLY_MODE", cast=bool, default=False)
    TERMINAL_READ_MODE: bool = config("TERMINAL_READ_MODE", cast=bool, default=False)
    # --------------------------------------------------------------------------
    #
    # GEO CONFIG
    #
    # --------------------------------------------------------------------------
    # It is required to do a free registration and create a license key
    GEO_LICENSE_KEY: Union[str, None] = config("GEO_LICENSE_KEY", default=None)
    # docs: https://dev.maxmind.com/geoip/geoip2/geolite2/
    GEO_LITE_TAR_FILE_URL = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-City"
        f"&license_key={GEO_LICENSE_KEY}"
        f"&suffix=tar.gz"
    )
    # TODO: add legacy
    # http://dev.maxmind.com/geoip/legacy/geolite/
    GEO_DB_FNAME = "/GeoLite2-City.mmdb"
    GEO_DB_ZIP_FNAME = "/GeoIP2LiteCity.tar.gz"
    # --------------------------------------------------------------------------
    #
    # RECON CONFIG
    #
    # --------------------------------------------------------------------------
    # Set your API keys here
    SECRET_CENSYS_USERNAME: Union[str, None] = config('CENSYS_USERNAME', default=None)
    SECRET_CENSYS_SECRET: Union[str, None] = config('CENSYS_SECRET', default=None)
    SECRET_SHODAN_API_KEY: Union[str, None] = config('SHODAN_API_KEY', default=None)
    SECRET_VIRUSTOTAL_API_KEY: Union[str, None] = config(
        'VIRUSTOTAL_API_KEY', default=None
    )
    SECRET_PASSIVE_TOTAL_USERNAME: Union[str, None] = config(
        'PASSIVE_TOTAL_USERNAME', default=None
    )
    SECRET_PASSIVE_TOTAL_KEY: Union[str, None] = config(
        'PASSIVE_TOTAL_KEY', default=None
    )
    SECRET_SECURITY_TRAILS_KEY: Union[str, None] = config(
        'SECURITY_TRAILS_KEY', default=None
    )
    SECRET_RIDDLER_EMAIL: Union[str, None] = config('RIDDLER_EMAIL', default=None)
    SECRET_RIDDLER_PASSWORD: Union[str, None] = config('RIDDLER_PASSWORD', default=None)
    SECRET_INSTAGRAM_SSID: Union[str, None] = config('INSTAGRAM_SSID', default=None)

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def print(self) -> None:
        if self.LOGGING_LEVEL == logging.getLevelName(logging.DEBUG):
            print()
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            logging.log(
                verboselogs.VERBOSE,
                f"PROJECT_NAME           : {Bold(self.PROJECT_NAME)}",
            )
            logging.log(
                verboselogs.VERBOSE, f"VERSION                : {Bold(self.VERSION)}"
            )
            logging.log(
                verboselogs.VERBOSE, f"ENV_MODE               : {Bold(self.ENV_MODE)}"
            )
            logging.log(
                verboselogs.VERBOSE,
                f"LOGGING-LEVEL          : {Bold(self.LOGGING_LEVEL)}",
            )
            logging.log(
                verboselogs.VERBOSE,
                f"LOGGING-VERBOSE        : {Bold(self.LOGGING_VERBOSE)}",
            )
            logging.log(
                verboselogs.VERBOSE,
                f"DISABLED SPLIT PROJECT : {Bold(self.DISABLE_SPLIT_PROJECT)}",
            )
            logging.log(
                verboselogs.VERBOSE,
                f"DISABLED SPLIT HOST    : {Bold(self.DISABLE_SPLIT_HOST)}",
            )
            logging.log(
                verboselogs.VERBOSE,
                f"PRINT ONLY MODE        : {Bold(self.PRINT_ONLY_MODE)}",
            )
            # logging.log(
            #     verboselogs.VERBOSE,
            #     f'PROJECT-PATH           : {Bold(create_service_path(None))}{Bold("/")}',
            # )
            logging.log(
                verboselogs.VERBOSE, f"ENV-MODE               : {Bold(self.ENV_MODE)}"
            )
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            print()


settings = Settings()
