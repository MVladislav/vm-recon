import logging as logger
import os
import re
import subprocess
import sys
import time
import unicodedata
from pathlib import Path
from shutil import which

import coloredlogs
import verboselogs

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class Utils:

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def __init__(self, ctx):
        self.ctx = ctx

        if self.ctx.verbose == 0:
            log_level = logger.INFO
            log_format = '%(message)s'
        elif self.ctx.verbose == 1:
            log_level = logger.INFO
            log_format = '%(levelname)-7s - %(message)s'
        elif self.ctx.verbose == 2:
            log_level = logger.DEBUG
            log_format = '%(levelname)-7s - %(message)s'
        elif self.ctx.verbose == 3:
            log_level = logger.DEBUG
            log_format = '[%(lineno)-6d: (%(funcName)-30s)]:: %(levelname)-7s - %(message)s'
        elif self.ctx.verbose > 3:
            log_level = logger.DEBUG
            log_format = '[%(asctime)s,%(msecs)03d] %(name)s[%(process)d] {%(lineno)-6d: (%(funcName)-30s)} %(levelname)-7s - %(message)s'

        self.logging = verboselogs.VerboseLogger('vm_logger')
        self.logging.addHandler(logger.StreamHandler(sys.stdout))
        coloredlogs.install(level=log_level, fmt=log_format, logger=self.logging)

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def log_runBanner(self, msg: str) -> None:
        self.logging.info(f"[+] Running {msg}...")

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def create_folder(self, path: str) -> None:
        Path(path).mkdir(parents=True, exist_ok=True, mode=0o700)

    def get_user_path(self) -> str:
        return str(Path.home())

    def create_service_folder(self, name: str) -> str:
        path = f'{self.ctx.base_path}{"" if self.ctx.project == None else f"/{self.ctx.project}"}/{name}'
        self.create_folder(path)
        return path

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def run_command_endless(self, command_list=[]) -> None:
        sub_p: subprocess.Popen = None
        is_running = True
        try:
            index_to_check = 0
            index_to_check = 1 if command_list[index_to_check] == "sudo" else index_to_check

            if self.is_tool(command_list[index_to_check]):
                sub_p = subprocess.Popen(command_list)
                while is_running:
                    time.sleep(600)
            else:
                self.logging.error(f"the command '{command_list[index_to_check]}', did not exist")
        # termination with Ctrl+C
        except KeyboardInterrupt:
            print("process killed!")
        except Exception as e:
            self.logging.exception(e)
        is_running = False
        try:
            if sub_p != None:
                sub_p.terminate()
        except:
            pass
        try:
            if sub_p != None:
                while sub_p.poll() == None:
                    time.sleep(1)
        except:
            pass

    def run_command(self, command_list=[], input: str = None, inner_loop: bool = False) -> str:
        sub_p = None
        result = None
        try:
            index_to_check = 0
            index_to_check = 1 if command_list[index_to_check] == "sudo" else index_to_check

            if self.is_tool(command_list[index_to_check]):
                if input == None:
                    sub_p: subprocess.CompletedProcess = subprocess.run(command_list, stdout=subprocess.PIPE)  # , shell=True
                    result = sub_p.stdout
                else:
                    sub_p: subprocess.Popen = subprocess.Popen(command_list, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                    sub_p = sub_p.communicate(input.encode())[0]
                    result = sub_p
            else:
                self.logging.error(f"the command '{command_list[index_to_check]}', did not exist")
        # termination with Ctrl+C
        except KeyboardInterrupt as k:
            if sub_p != None and type(sub_p) == subprocess.Popen:
                sub_p.kill()
            self.logging.debug(f"process interupted! ({k})")
            if inner_loop:
                raise KeyboardInterrupt
        except Exception as e:
            self.logging.exception(e)
        if result != None:
            return result.decode()

    def is_tool(self, name: str) -> bool:
        """Check whether `name` is on PATH and marked as executable."""
        return which(name) is not None

    def run_command_output_loop(self, msg: str, cmds=[], output: bool = True) -> str:
        self.log_runBanner(msg)
        cmd_result = None
        try:
            for cmd in cmds:
                self.logging.debug(" ".join(cmd))
                if output:
                    cmd_result = self.run_command(command_list=cmd, input=cmd_result, inner_loop=True)
                else:
                    cmd_result = self.run_command(command_list=cmd, inner_loop=True)
                if cmd_result != None and len(cmd_result) > 0:
                    self.logging.notice(cmd_result)
            return cmd_result
        except KeyboardInterrupt as k:
            self.logging.debug(f"process interupted! ({k})")
        return cmd_result

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def slugify(self, value, allow_unicode=False):
        """
        https://github.com/django/django/blob/main/django/utils/text.py
        """
        value = str(value)
        if allow_unicode:
            value = unicodedata.normalize('NFKC', value)
        else:
            value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
        value = re.sub(r'[^\w\s-]', '', value.lower())
        return re.sub(r'[-\s]+', '-', value).strip('-_')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def in_sudo_mode(self):
        """If the user doesn't run the program with super user privileges, don't allow them to continue."""
        if not 'SUDO_UID' in os.environ.keys():
            self.logging.error("Try running this program with sudo.")
            sys.exit(1)
