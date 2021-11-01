import logging
import os
import pprint
import shutil
import socket
import sys
import tarfile
from typing import Dict

import maxminddb
import requests
from stringcolor import bold

from ..utils.utils import Context, Utils
from .config import GEO_DB_FNAME, GEO_DB_ZIP_FNAME, GEO_LITE_TAR_FILE_URL

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class Locator:
    """
        data_file => optional | else will used default defined in config
        USAGE:
            locate = Locator(url=url, ip=ip, data_file=datafile)
            locate.check_database()
            locate.query()
    """

    def __init__(self, ctx: Context, url: str = None, ip: str = None, data_file: str = None):
        self.utils: Utils = ctx.utils
        self.url = url
        self.ip = ip
        self.path = self.utils.create_service_folder(f'GeoIP', ip)
        self.data_file = data_file
        self.target = ''

    def check_database(self) -> None:
        try:
            if not self.data_file:
                self.data_file = f'{self.path}{GEO_DB_FNAME}'
            else:
                if not os.path.isfile(self.data_file):
                    logging.log(logging.WARNING, 'Failed to Detect Specified Database')
                    # NOTE: sys.exit(1)
                else:
                    return

            if not os.path.isfile(self.data_file):
                logging.log(logging.WARNING, 'Default Database Detection Failed')
                try:
                    database_choice: str = input(f'[*] Attempt to Auto-install_package Database? {bold("[y/N]")}')
                except KeyboardInterrupt:
                    logging.log(logging.WARNING, 'User Interrupted Choice')
                    # NOTE: sys.exit(1)

                if database_choice.strip().lower()[0] == 'y':
                    logging.log(logging.INFO, 'Attempting to Auto-install_package Database... ')
                    sys.stdout.flush()
                    if not os.path.isdir(self.path):
                        os.makedirs(self.path)

                    try:
                        url = GEO_LITE_TAR_FILE_URL
                        response = requests.get(url)

                        with open(f'{self.path}{GEO_DB_ZIP_FNAME}', 'wb') as f:
                            f.write(response.content)
                            f.flush()
                    except Exception as ex:
                        logging.log(logging.CRITICAL, '[FAIL]', ex)
                        logging.log(logging.WARNING, 'Failed to Download Database')
                        # NOTE: sys.exit(1)

                    try:
                        my_tar: tarfile.TarFile = tarfile.open(f'{self.path}{GEO_DB_ZIP_FNAME}')
                        extract_file: str = [name for name in my_tar.getnames() if 'mmdb' in name][0]
                        my_tar.extract(extract_file, self.path)
                        my_tar.close()
                        os.remove(f'{self.path}{GEO_DB_ZIP_FNAME}')
                        shutil.move(f'{self.path}/{extract_file}', f'{self.path}{GEO_DB_FNAME}')
                    except IOError as ioe:
                        logging.log(logging.CRITICAL, '[FAIL]', ioe)
                        logging.log(logging.WARNING, 'Failed to Decompress Database')
                        # NOTE: sys.exit(1)

                    logging.log(logging.INFO, '[DONE]')
                elif database_choice.strip().lower()[0] == 'n':
                    logging.log(logging.WARNING, 'User Denied Auto-Install')
                    # NOTE: sys.exit(1)
                else:
                    logging.log(logging.WARNING, 'Invalid Choice')
                    # NOTE: sys.exit(1)
        except Exception as e:
            logging.log(logging.CRITICAL, e)

    def query(self) -> None:
        try:
            if self.url is not None:
                logging.log(logging.INFO, f'Translating {self.url}')
                sys.stdout.flush()
                try:
                    self.target += socket.gethostbyname(self.url)
                    logging.log(logging.INFO, self.target)
                except Exception as ex:
                    logging.log(logging.WARNING, 'Failed to Resolve URL', ex)
                    return
            elif self.ip is not None:
                self.target += self.ip
            else:
                logging.log(logging.WARNING, 'URL or IP is need to be defined')
                return

            try:
                logging.log(logging.INFO, f'Querying for Records of {self.target}')

                with maxminddb.open_database(self.data_file) as reader:
                    data: Dict = reader.get(self.target)
                    pprint.pprint(data)
                    logging.log(logging.INFO, 'Query Complete!')
            except Exception as ex:
                logging.log(logging.WARNING, 'Failed to Retrieve Records', ex)
                return
        except Exception as e:
            logging.log(logging.CRITICAL, e)
