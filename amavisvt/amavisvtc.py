#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import socket
import sys
from argparse import ArgumentParser
from setproctitle import setproctitle

from amavisvt.config import Configuration

BUFFER_SIZE = 4096

class AmavisVTClient(object):

    def __init__(self, socket_path):
        self.config = Configuration()
        self.socket_path = socket_path or self.config.socket_path

    def execute(self, command, *arguments):
        logger.debug("Executing command '%s' with args: %s", command, arguments)

        translate = {
            'ping': 'PING',
            'scan': 'CONTSCAN',
            'report': 'REPORT',
        }

        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.socket_path)

            # send absolute paths to amavisvtd
            absolute_args = [os.path.abspath(p) for p in arguments]
            s = "%s %s" % (translate.get(command, command.upper()), ' '.join(absolute_args))

            payload = s.strip() + "\n"
            sock.sendall(payload.encode('utf-8'))

            data = sock.recv(BUFFER_SIZE)
            return data.decode('utf-8')
        finally:
            if sock:
                sock.close()


if __name__ == "__main__":  # pragma: no cover
    setproctitle("amavisvtd")
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity', default=2)
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='Send verbose log messages to stdout too')
    parser.add_argument('-s', '--socket', help='Socket path')
    parser.add_argument('command', choices=('ping', 'scan', 'report'))
    parser.add_argument('command_args', nargs='*')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.FATAL - (10 * args.verbose),
        format='%(asctime)s %(levelname)-7s [%(threadName)s] %(message)s',
    )

    logger = logging.getLogger()

    if not args.debug:
        for h in logger.handlers:
            h.setLevel(logging.ERROR)

    if not args.command.lower() in ('ping', 'scan', 'report'):
        print("Invalid command: %s" % args.command)
        sys.exit(1)

    error = False
    try:
        client = AmavisVTClient(args.socket)
        response = client.execute(args.command, *tuple(args.command_args))
        error = response.startswith('ERROR:')

        print(response)
    except Exception as ex:
        error = True
        logger.exception("Command '%s' failed", args.command)
        print(ex)
    finally:
        sys.exit(int(error))
