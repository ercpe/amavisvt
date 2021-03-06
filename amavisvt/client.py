# -*- coding: utf-8 -*-
import base64
import email
import hashlib
import logging
import os
import re
import shutil
import tempfile
from email.utils import parseaddr

import memcache
import requests
import sys

from amavisvt import VERSION
from amavisvt.db import Database
from amavisvt.db.base import NoopDatabase

MAIL_MIME_TYPE = 'message/rfc822'

logger = logging.getLogger(__name__)

BUFFER_SIZE = 4096


def clean_silent(paths):
    for p in paths if isinstance(paths, list) else [paths]:
        try:
            logger.debug("Cleaning up: %s", p)
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
        except:
            logger.exception("Could not remove %s", p)


magic_identify_buffer = None


def python_magic_id_buffer(buf):
    import magic
    t = magic.from_buffer(buf, mime=True)
    if t and isinstance(t, bytes) and sys.version_info > (3,):
        t = t.decode('UTF-8', 'ignore')
    return t


def filemagic_id_buffer(buf):
    import magic
    with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as mgc:
        return mgc.id_buffer(buf)


try:
    import magic

    if hasattr(magic, 'from_buffer'):
        # python-magic
        identify_buffer = python_magic_id_buffer
    elif hasattr(magic, 'MAGIC_MIME_TYPE'):
        # filemagic
        identify_buffer = filemagic_id_buffer
    else:
        raise Exception("No suitable libmagic library found. Please install either filemagic or python-magic")

except ImportError:
    raise


class VTResponse(object):
    def __init__(self, virustotal_response):
        self._data = virustotal_response
        self.infected = False

    resource = property(lambda self: self._data['resource'])
    response_code = property(lambda self: self._data['response_code'])
    verbose_message = property(lambda self: self._data.get('verbose_msg', ''))
    md5 = property(lambda self: self._data.get('md5'))
    permalink = property(lambda self: self._data.get('permalink'))
    positives = property(lambda self: int(self._data.get('positives', 0)))
    scan_date = property(lambda self: self._data.get('scan_date'))
    scan_id = property(lambda self: self._data.get('scan_id'))
    scans = property(lambda self: self._data.get('scans'))
    sha1 = property(lambda self: self._data.get('sha1'))
    sha256 = property(lambda self: self._data.get('sha256'))
    total = property(lambda self: self._data.get('total'))

    def __str__(self):
        return "%s: %s" % (self.resource, self.verbose_message or '<no message>')


class FilenameResponse(VTResponse):

    def __init__(self, reported=False):
        super(FilenameResponse, self).__init__(virustotal_response={
            'resource': '<filename>',
            'scans': {
                'filename pattern': {
                    'detected': True,
                    'result': 'filename pattern matches infected files%s' % (
                        ', reported' if reported else ''
                    )
                }
            },
            'positives': 1,
            'total': 1,
            'sha256': '',
        })
        self.infected = True


class ResourceSet(object):
    def __init__(self, resources):
        self.resources = resources or []
        self._to_addresses = None

    def __len__(self):
        return len(self.resources)

    @property
    def to_addresses(self):
        if self._to_addresses is None:
            self.find_recipients()
        return self._to_addresses

    @property
    def to_localpart(self):
        if not self.to_addresses:
            return None

        to = self.to_addresses[0]
        if '@' in to:
            return to.split('@')[0]

    @property
    def to_domain(self):
        if not self.to_addresses:
            return None

        to = self.to_addresses[0]
        if '@' in to:
            return to.split('@')[1]

    def find_recipients(self):
        addresses = []

        for r in self.resources:
            if r.mime_type == MAIL_MIME_TYPE:
                addresses.extend(self.extract_addresses(r))

        self._to_addresses = list(set(addresses))

    @staticmethod
    def extract_addresses(resource):
        l = []

        try:
            with open(resource.path) as f:
                msg = email.message_from_file(f)
                recipient = msg.get('To', '')
                if recipient:
                    logger.info("TO header: '%s'", recipient)
                    _, email_address = parseaddr(recipient)
                    if email_address:
                        l.append(email_address)
        except:
            logger.exception("Could not extract 'To' header from resource %s", resource)

        return l

    def __iter__(self):
        return iter(self.resources)


class Resource(object):

    def __init__(self, path, **kwargs):
        self.path = path
        self._filename = kwargs.get('filename', None)
        self._no_unpack = kwargs.get('no_unpack', False)
        self.cleanup = kwargs.get('cleanup', True)
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._mime_type = None
        self._size = None

    @property
    def md5(self):
        if self._md5 is None:
            self.examine()
        return self._md5

    @property
    def sha1(self):
        if self._sha1 is None:
            self.examine()
        return self._sha1

    @property
    def sha256(self):
        if self._sha256 is None:
            self.examine()
        return self._sha256

    @property
    def mime_type(self):
        if self._mime_type is None:
            self.examine()
        return self._mime_type

    @property
    def size(self):
        if self._size is None:
            self._size = os.path.getsize(self.path)
        return self._size

    @property
    def can_unpack(self):
        return self.mime_type in (MAIL_MIME_TYPE,) and not self._no_unpack

    @property
    def filename(self):
        return self._filename or os.path.basename(self.path)

    def __iter__(self):
        for x in self._iter_unpacked(self, 10): # todo: make depth configurable
            yield x

    def _iter_unpacked(self, resource, depth):
        if depth <= 0:
            logger.warning("Reached maximum unpack depth - further sub resources will not be checked!")
            return

        if resource.can_unpack:
            for subresource in resource.unpack():
                yield subresource
                for subsubresource in self._iter_unpacked(subresource, depth-1):
                    yield subsubresource

    def examine(self):
        logger.debug("Examine %s", self.path)
        md5hasher = hashlib.md5()
        sha1hasher = hashlib.sha1()
        sha256hasher = hashlib.sha256()

        id_buffer = b""

        with open(self.path, 'rb') as f:
            tmp = f.read(BUFFER_SIZE)
            while tmp:
                if len(id_buffer) < BUFFER_SIZE * 4:
                    id_buffer += tmp

                md5hasher.update(tmp)
                sha1hasher.update(tmp)
                sha256hasher.update(tmp)
                tmp = f.read(BUFFER_SIZE)

        self._md5 = md5hasher.hexdigest()
        self._sha1 = sha1hasher.hexdigest()
        self._sha256 = sha256hasher.hexdigest()

        self._mime_type = identify_buffer(id_buffer)
        logger.debug("libmagic identified %s as: %s", self, self._mime_type)

        # This is a hacky way to detect mail messages. Sometimes, when the amount of other text data exceeds the
        # amount of "mail-like" data in a file (like a mail message with lots of HTML), libmagic fails to detect
        # the file as a mail message.
        if self._mime_type in ('text/plain', 'text/html'):
            try:
                msg = email.message_from_string(id_buffer.decode('utf-8'))
                if len(msg.keys()) and 'From' in msg and 'To' in msg:
                    logger.debug("Identified mail in %s when libmagic could not (said it was %s)", self.filename, self.mime_type)
                    self._mime_type = MAIL_MIME_TYPE
            except:
                pass

    def unpack(self):
        unpack_func = None

        if self.mime_type == MAIL_MIME_TYPE:
            unpack_func = self.unpack_mail

        try:
            for res in unpack_func():
                yield res
        except:
            logger.exception("Error unpacking %s" % self)

    def unpack_mail(self):
        try:
            with open(self.path) as f:
                msg = email.message_from_file(f)

            sender = msg.get('From', '<not set>')
            recipient = msg.get('To', '<not set>')
            logger.info("Mail from %s to %s", sender, recipient)

            payload = msg.get_payload()

            if isinstance(payload, list):
                for part in self.unpack_mail_payload(payload):
                    yield part
            else:
                # single payload message. Since it's possible that the only payload is the message itself and the
                # payload is an attachment we need this extra block
                ct = msg.get_content_type() if 'Content-Type' in msg else None
                
                if ct and not ct.startswith('text/'):  # exclude common single payloads
                    try:
                        res = Resource._extract_mailpart(msg.get_payload(), msg.get_filename())
                        
                        if res and AmavisVT.is_included(res):
                            logger.info("Found a single, included payload in mail")
                            yield res
                        
                    except:
                        logger.exception("Could not single payload from mail")

                else:
                    logger.debug("Skipping single payload message (Content-Type: %s)", ct)

        except:
            logger.exception("Failed to parse mail file %s", self.path)

    @staticmethod
    def unpack_mail_payload(payload):
        for i, part in enumerate(payload):
            if not isinstance(part, email.message.Message):
                logging.debug("Skipping non-message payload")
                continue

            logger.debug("Mailpart %s", i)
            for k, v in part.items():
                logger.debug(" %s: %s", k, v)

            filename = part.get_filename()
            partname = "part%s" % i

            if not filename:
                continue

            try:
                res = Resource._extract_mailpart(part.get_payload(), filename)
                if res:
                    logger.debug("Mail part %s (%s): orig filename: %s, mime type: %s", i, res.path, filename,
                                 res.mime_type)
                    yield res
            except:
                logger.exception("Could not extract attachment %s", partname)

    @staticmethod
    def _extract_mailpart(payload, filename):
    
        if len(payload) > 27892121:  # roughly 20 MiB as base64
            logger.warning("Skipping part (larger than 20MiB")
            return

        fd, temp_path = tempfile.mkstemp('-mailpart', prefix='amavisvt-')
        try:
            os.write(fd, base64.b64decode(payload))
        finally:
            os.close(fd)

        return Resource(temp_path, filename=filename)

    def __str__(self):
        return self.filename


class AmavisVT(object):
    buffer_size = 4096

    def __init__(self, config, memcached_servers=None):
        self.config = config
        self.memcached = memcache.Client(memcached_servers or ['127.0.0.1:11211']) # NOSONAR
        try:
            self.database = Database(config)
        except:
            logger.exception("Error opening database")
            self.database = NoopDatabase(config)

        self.clean_paths = []

    def run(self, file_or_directory):
        resources = []

        if os.path.isfile(file_or_directory):
            if os.access(file_or_directory, os.R_OK):
                resources.append(Resource(file_or_directory, cleanup=False))
            else:
                logger.info("Skipping inaccessible file %s", file_or_directory)
        elif os.path.isdir(file_or_directory):
            for root, dirs, files in os.walk(file_or_directory):
                for f in files:
                    p = os.path.join(root, f)

                    if not os.path.isfile(p):
                        continue

                    if os.access(p, os.R_OK):
                        resources.append(Resource(p, cleanup=False))
                    else:
                        logger.info("Skipping inaccessible file %s", file_or_directory)

        return self.process(ResourceSet(resources))

    def process(self, resource_set):
        hashes_for_vt = []
        results = []

        try:
            def _iter_resources():
                for r in resource_set:
                    yield r
                    for x in r:
                        yield x

            all_resources = list(_iter_resources())
            logger.info("Processing %s resources: %s", len(all_resources), ', '.join([r.path for r in all_resources]))

            for resource in all_resources:
                if resource.cleanup:
                    self.clean_paths.append(resource.path)

                if self.is_included(resource):
                    cached_value = self.get_from_cache(resource.sha256)

                    if cached_value:
                        logger.info("Using cached result for file %s (%s): %s", resource, resource.sha256, cached_value)
                        results.append((resource, cached_value))
                    else:
                        hashes_for_vt.append((resource, resource.sha256))
                else:
                    logger.debug("Skipping resource (not included): %s", resource)
                    continue

            logger.info("Sending %s hashes to Virustotal", len(hashes_for_vt))
            vt_results = list(self.check_vt(hashes_for_vt))
            results.extend(vt_results)

            if self.config.filename_pattern_detection:
                logger.debug("Filename pattern detection enabled")
                results.extend(self.do_filename_pattern_detection(hashes_for_vt, resource_set, vt_results))

            # update patterns for entries which have no pattern set yet
            self.database.update_patterns()

            return [(resource, response) for resource, response in results if response]
        finally:
            clean_silent(self.clean_paths)
            self.database.clean()

    def do_filename_pattern_detection(self, hashes_for_vt, resource_set, vt_results):
        results = []
        for resource, sha256 in hashes_for_vt:
            vtresult = [r for _, r in vt_results if r and r.sha256 == sha256]
            vtresult = vtresult[0] if vtresult else None

            # add the resource to the database
            self.database.add_resource(resource, vtresult, resource_set.to_localpart, resource_set.to_domain)

            # only test for filename pattern if the resource hasn't identified as infected by its hash
            if vtresult is None and self.database.filename_pattern_match(resource, localpart=resource_set.to_localpart):
                logger.info("Flagging attachment %s as INFECTED (identified via filename pattern)", resource.filename)

                try:
                    results.remove((resource, vtresult))
                except ValueError:
                    pass

                reported = False

                if self.config.auto_report:
                    reported = self.report_to_vt(resource)

                results.append((resource, FilenameResponse(reported)))
        return results

    @staticmethod
    def is_included(resource):
        return any((f(resource) for f in [
                    lambda r: r.mime_type.startswith('application/'),
                    lambda r: r.mime_type in ('text/x-shellscript', 'text/x-perl', 'text/x-ruby', 'text/x-python'),
                    lambda r: re.search(r"\.(exe|com|zip|tar\.[\w\d]+|doc\w?|xls\w?|ppt\w?|pdf|js|bat|cmd|rtf|ttf|html?|vbs|wsf)$", r.filename, re.IGNORECASE),
                    lambda r: '.' not in r.filename or r.filename.endswith('.')
        ]))

    def check_vt(self, checksums):
        if self.config.pretend:
            logger.info("NOT sending requests to virustotal")
            return

        if not checksums:
            return

        max_hashes_per_request = 4 # Virustotal's public api limit
        extra_hashes = max_hashes_per_request - len(checksums)
        if extra_hashes < 0:
            extra_hashes = 0

        try:
            # create a dictionary of sha256 <> filename
            query_d = dict((v, k) for k, v in checksums)

            raw_checksums = [x[1] for x in checksums]

            # get hashes from database that have a pattern but infected=0
            if extra_hashes > 0:
                clean_hashes = self.database.get_clean_hashes(extra_hashes)
                logger.info("Piggy backing request to VT to send %s extra hashes" % len(clean_hashes))
            else:
                clean_hashes = []

            send_checksums = sorted(list(set(raw_checksums + clean_hashes)))
            logger.debug("Sending %s checksums", len(send_checksums))

            response = requests.post(self.config.api_url, {
                'apikey': self.config.apikey,
                'resource': ', '.join(send_checksums)
            }, timeout=float(self.config.timeout), headers={
                'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
            })
            response.raise_for_status()
            if response.status_code == 204:
                raise Exception("API-Limit exceeded!")

            responses = response.json()
            if not isinstance(responses, list):
                responses = [responses]
            logger.debug("Got %s items in response", len(responses))
            responses = dict((d['sha256'], d) for d in responses if 'sha256' in d)
            logger.debug("Got %s complete items in response", len(responses))

            for sha256, data in responses.items():
                vtr = VTResponse(data)
                vtr.infected = self.is_infected(vtr)

                cache_expires = self.config.unknown_expire
                if vtr.response_code:
                    cache_expires = self.config.positive_expire if vtr.infected else self.config.negative_expire

                logger.info("Saving in cache: %s (expires in %s seconds)", vtr.sha256, cache_expires)
                self.set_in_cache(vtr.resource, data, cache_expires)

                logger.info("Updating database result for %s (infected: %s)", vtr.sha256, vtr.infected)
                self.database.update_result(vtr)

                if sha256 in query_d:
                    filename = query_d[sha256]
                    logger.debug("Result for %s: %s" % (filename, vtr))
                    yield filename, vtr

        except:
            logger.exception("Error asking virustotal about files")

    def report_to_vt(self, resource):
        if self.config.pretend:
            logger.info("NOT sending resource to virustotal")
            return

        try:
            logger.info("Reporting resource %s (%s) to virustotal", resource, resource.filename)

            files = {
                'file': (resource.filename, open(resource.path, 'rb')),
            }
            response = requests.post(self.config.report_url, data={
                                        'apikey': self.config.apikey,
                                    },
                                    files=files,
                                    timeout=float(self.config.timeout),
                                    headers={
                                        'User-Agent': 'amavisvt/%s (+https://ercpe.de/projects/amavisvt)' % VERSION
                                    })
            response.raise_for_status()
            if response.status_code == 204:
                raise Exception("API-Limit exceeded!")

            vtr = VTResponse(response.json())
            logger.info("Report result: %s", vtr)
            return vtr
        except:
            logger.exception("Error reporting %s to virustotal", resource)
            return False

    def get_from_cache(self, sha256hash):
        from_cache = self.memcached.get(sha256hash)
        if from_cache:
            vtr = VTResponse(from_cache)
            vtr.infected = self.is_infected(vtr)
            return vtr

    def set_in_cache(self, sha256hash, d, expire=0):
        logger.debug("Saving key %s in cache. Expires in %s seconds", sha256hash, expire)
        self.memcached.set(sha256hash, d, time=expire)

    def is_infected(self, response_or_positive_hits):
        if isinstance(response_or_positive_hits, VTResponse):
            return response_or_positive_hits.positives >= self.config.hits_required
        return int(response_or_positive_hits) >= self.config.hits_required
