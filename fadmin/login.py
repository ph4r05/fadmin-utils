#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import requests
import argparse
import time
import re
import logging
import coloredlogs
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


URL = 'https://fadmin.fi.muni.cz/auth/sit/wireless/login2.mpl'


def entry(args):
    if args.user is None:
        raise ValueError('Please use --user')

    if args.key_file:
        with open(args.key_file) as fh:
            password = fh.read().strip()

    elif args.key_ring:
        import keyring
        keyring.get_keyring()
        password = keyring.get_password(URL, args.user)

    else:
        raise ValueError('Password not specified')

    logger.info('Starting authentication loop')
    s = requests.Session()
    while True:
        try:
            res = s.get(URL, auth=HTTPBasicAuth(args.user, password), timeout=30)
            logger.debug(res.status_code)

            matches = re.findall(r'"(https://.+?)"', res.text)
            for m in matches:
                if 'thetis' not in m:
                    continue

                if args.no_ipv6 and 'ip6' in m:
                    continue

                try:
                    r = s.get(m, timeout=30)
                    logger.debug('Resp %s to %s' % (r.status_code, m))

                except Exception as e:
                    logger.warning('Exc: %s' % e)

            time.sleep(args.timeout)

        except Exception as e:
            logger.error('Exception: %s' % e)
            time.sleep(30)


def main():
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

    # fmt: on
    args = parser.parse_args()
    if args.debug:
        coloredlogs.install(level=logging.DEBUG, use_chroot=False)

    entry(args)


if __name__ == "__main__":
    main()
