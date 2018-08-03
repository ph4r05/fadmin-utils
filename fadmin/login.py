#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import requests
import argparse
import time
import re
import os
import logging
import coloredlogs
import threading
from multiping import MultiPing
from requests.auth import HTTPBasicAuth
from fadmin.trace_logger import Tracelogger

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


URL = 'https://fadmin.fi.muni.cz/auth/sit/wireless/login2.mpl'
FADMIN_HOST = 'fadmin.fi.muni.cz'
MUNI_HOST = 'muni.cz'


class Login(object):
    def __init__(self):
        self.args = None
        self.password = None
        self.sess = None

        self.running = True
        self.stop_event = threading.Event()
        self.trace_logger = Tracelogger(logger)
        self.auth_attempts = []

        self.ping_thread = [None, None]
        self.last_ping_time = [None, None]
        self.result_window = [[], []]
        self.window_length = 100
        self.monitored = [FADMIN_HOST, MUNI_HOST]

    def ping_main(self, monitored_host):
        """
        Main ping diagnostic thread
        :return:
        """
        logger.info('Ping thread started %s %s %s %s'
                    % (monitored_host, os.getpid(), os.getppid(), threading.current_thread()))

        try:
            while not self.stop_event.is_set():
                try:
                    cur_time = time.time()
                    self.ping_job(monitored_host)
                    self.last_ping_time[monitored_host] = cur_time
                    time.sleep(1)

                except Exception as e:
                    logger.error('Exception in ping job: %s' % e)
                    self.trace_logger.log(e)
                    time.sleep(5)

        except Exception as e:
            logger.error('Exception: %s' % e)
            self.trace_logger.log(e)

        logger.info('Ping loop %s terminated' % monitored_host)

    def ping_job(self, monitored_host, attempts=3, timeout=1):
        """
        Ping diagnosis
        :param monitored_host:
        :param attempts:
        :param timeout:
        :return:
        """
        mp = MultiPing([self.monitored[monitored_host]])
        mp.send()

        # With a 1 second timeout, wait for responses (may return sooner if all results are received).
        responses, no_responses = mp.receive(timeout)
        succ_rtt = None

        for addr, rtt in responses.items():
            succ_rtt = succ_rtt if rtt is None else min(succ_rtt, rtt)

        self.result_window[monitored_host].append(succ_rtt)
        if len(self.result_window[monitored_host]) > self.window_length:
            self.result_window[monitored_host].pop(0)

    def has_enough_data(self):
        return len(self.result_window[0]) > 3

    def is_on_fi(self):
        suffix = self.result_window[0][-3:]
        return sum([1 for x in suffix if x is not None]) >= 2  # At least 2 in 3 last measurements

    def is_world_pingable(self):
        suffix = self.result_window[1][-3:]
        return sum([1 for x in suffix if x is not None]) >= 2  # At least 2 in 3 last measurements

    def prune_attempts(self):
        self.auth_attempts = self.auth_attempts[-100:]  # keep last 100 records

    def last_auths_in(self, num, span):
        last = self.auth_attempts[-num:]
        if len(last) < num:
            return False

        return sum([1 for x in last if x[0] > span]) == num

    def reauth_target(self):
        if len(self.auth_attempts) == 0:
            return 0

        cur_time = time.time()
        last = self.auth_attempts[-1]

        # World is not pingable, get time to start auth.
        if not self.is_world_pingable():
            # If last 20 auths were within 5 minute, slow down to 5 minutes
            if self.last_auths_in(20, cur_time - 5 * 60):
                return cur_time + 5*60
            # If last 10 auths were within 1 minute, slow down to 30 sec
            if self.last_auths_in(10, cur_time - 30):
                return cur_time + 30
            # If last 2 reauths in 5 seconds:
            if self.last_auths_in(2, cur_time - 5):
                return cur_time + 2
            return last[0] + 1

        # World is pingable
        if last[1]:
            return last[0] + self.args.timeout  # last auth OK
        else:
            if self.last_auths_in(20, cur_time - 5 * 60):
                return cur_time + 5 * 60
            if self.last_auths_in(10, cur_time - 30):
                return cur_time + 30
            if self.last_auths_in(2, cur_time - 5):
                return cur_time + 2
            return last[0] + 5  # last auth failed with exception

    def do_auth(self):
        res = self.sess.get(URL, auth=HTTPBasicAuth(self.args.user, self.password), timeout=30)
        logger.debug(res.status_code)

        matches = re.findall(r'"(https://.+?)"', res.text)
        for m in matches:
            if 'thetis' not in m:
                continue

            if self.args.no_ipv6 and 'ip6' in m:
                continue

            try:
                r = self.sess.get(m, timeout=30)
                logger.debug('Resp %s to %s' % (r.status_code, m))

            except Exception as e:
                logger.warning('Exc: %s' % e)

    def process_args(self):
        if self.args.user is None:
            raise ValueError('Please use --user')

        if self.args.key_file:
            with open(self.args.key_file) as fh:
                self.password = fh.read().strip()

        elif self.args.key_ring:
            import keyring
            keyring.get_keyring()
            self.password = keyring.get_password(URL, self.args.user)

        else:
            raise ValueError('Password not specified')

    def boot(self):
        self.ping_thread[0] = threading.Thread(target=self.ping_main, args=(0, ))
        self.ping_thread[0].setDaemon(True)
        self.ping_thread[0].start()

        self.ping_thread[1] = threading.Thread(target=self.ping_main, args=(1, ))
        self.ping_thread[1].setDaemon(True)
        self.ping_thread[1].start()

        self.sess = requests.Session()

    def entry(self, args):
        self.args = args
        self.process_args()
        self.boot()

        logger.info('Starting authentication loop')
        while True:
            # Check whether we have enough running information to decide what to do
            if not self.has_enough_data():
                time.sleep(0.2)
                continue

            # If not on FI network, put into rest
            if not self.is_on_fi():
                time.sleep(0.5)
                continue

            # Main reauth loop.
            # Timing depends on the current state, whether world is pingable, whether
            # the last auth was successful.
            res = False
            auth_called = False
            try:
                if time.time() >= self.reauth_target():
                    auth_called = True
                    self.do_auth()
                    res = True

            except Exception as e:
                logger.error('Exception: %s' % e)

            finally:
                if auth_called:
                    self.auth_attempts.append((time.time(), res))
                    self.prune_attempts()
                time.sleep(0.2)

    def main(self):
        parser = argparse.ArgumentParser(description="FI MUNI Agent utils")

        # fmt: off
        parser.add_argument("--sign", dest="sign", default=None,
                            help="Sign the unsigned file")

        parser.add_argument("--user", dest="user", default=None,
                            help="Username to login",)

        parser.add_argument("--key-file", dest="key_file", default=None,
                            help="password file",)

        parser.add_argument("--timeout", dest="timeout", default=60*30, type=int,
                            help="Request timeout",)

        parser.add_argument("--debug", dest="debug", default=False, action="store_const", const=True,
                            help="Debugging output",)

        parser.add_argument("--no-ipv6", dest="no_ipv6", default=False, action="store_const", const=True,
                            help="Debugging output",)

        parser.add_argument("--key-ring", dest="key_ring", default=False, action="store_const", const=True,
                            help="Use Key ring to obtain credentials",)

        parser.add_argument("--ping-check", dest="ping_check", default=False, action="store_const", const=True,
                            help="Ping network periodically, if problem is detected tries to reauth",)

        # fmt: on
        args = parser.parse_args()
        if args.debug:
            coloredlogs.install(level=logging.DEBUG, use_chroot=False)

        self.entry(args)


def main():
    l = Login()
    l.main()


if __name__ == "__main__":
    main()
