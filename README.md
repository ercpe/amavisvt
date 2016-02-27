`amavisvt` is a command-line program to include [Virustotal](https://virustotal.com) as an amavisd-new virus scanner by using the Virustotal Public API.

Before you think about integrating it into your mailserver, please have in mind that the Virustotal Public API has a very low request limit which isn't enough for most mail servers to provide good results.<br />
`amavisvt` uses memcached to reduce the number of calls to the API. While it's possible to run amavisvt without memached, it's strongly advised to do so.

`amavisvt` uses the SHA256 hash of mimeparts to fetch file scan reports from Virustotal. `amavisvt` **does not** send any content to virustotal. To reduce the number of requests to VT even further, `amavisvt` only asks for reports for parts whose mime type (identified by libmagic) starts with `application/`, `image/` or are typical scripts (perl, python, shell).

In future versions, `amavisvt` may integrate configurable filter for the mime types and/or file extensions.


# Installation

If you are on Gentoo Linux, add the [last hope overlay](https://ercpe.de/projects/last-hope-gentoo-portage-overlay) and emerge amavisvt:

    layman -a last-hope
    emerge app-antivirus/amavisvt -av


# Configuration

First, create an account on virustotal.com to obtain your API key. After registration, you can find it under "My API key"

`amavisvt` ships with an [example config file](https://code.not-your-server.de/amavisvt.git/blob/master/amavisvt_example.cfg). Place it in one of the following locations: `/etc/amavisvt.cfg`, `~/amavisvt.cfg` or `./amavisvt.cfg` and adjust it to your needs.

Please note, the location of memcached isn't configurable at the moment. The instance has to run on `127.0.0.1:11211` and must accept connections from localhost.

As a last step, configure amavisd-new by adding the following snippet to either `@av_scanners` or `@av_scanners_backup`:

    ['AmavisVT', 'amavisvt',
        '-v {}',
        [0], [1],
        qr/(?:Detected as) (.*)(?:\033|$)/m ],

After that, restart amavisd-new. If all went well, you should see a line like this in your logfile:

    Found primary av scanner AmavisVT    at /usr/bin/amavisvt


## License

See LICENSE.txt
