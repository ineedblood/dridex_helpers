# Copyright (c) 2016 Avira Operations GmbH & Co. KG.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# -------
#
# You can use this script to decrypt the new big Base64 settings responses
# in the HTTP protocol answers sent since Dridex version 3.188 (=196796).
#
# Requires the pycrypto package (pip install pycrypto).
#
# For more information see: http://blog.avira.com/dridex-starts-hardening-settings-files/

import sys
import struct
import base64
import hashlib
import re
from Crypto.PublicKey import RSA


pubkeystr = (
    '-----BEGIN PUBLIC KEY-----\n'
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQ02MVI4KvJW6jQHWOtyBeaCyT'
    'INAqDvgZFEM8FrSij5/Vs+QobLFR61YcZsMBZ3G2GzeB5n1j1sIOMW0+qTPxlyCO'
    'fBZbO5spvUPAkl0vFCWTda6y8RAowbD5c4jwBTxEIsaYI4AWKmDqesCq/qRyl6MA'
    'LAU/6Ahd2TsrwV5nHQIDAQAB'
    '\n-----END PUBLIC KEY-----'
)

serverpublickey = RSA.importKey(pubkeystr)


hash_oids = {
    "md5": "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    "sha1": "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "sha256": "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    "sha384": "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    "sha512": "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
}


def rsa_verify(sig, data, key, hashalgoname, nohashoid=False):
    """
    RSA signature verification function compatible to MS CryptVerifySignature using PKCS #7 padding
    """

    if hashalgoname not in hash_oids:
        raise ValueError("Unknown hash name!")

    hashdig = hashlib.new(hashalgoname, data).digest()
    hash_oid = hash_oids[hashalgoname]

    encodedsig = key.encrypt(sig[::-1], None)[0]
    if encodedsig[0] != '\x01':
        return False

    splitsig = encodedsig.split('\0', 1)
    if len(splitsig) != 2:
        return False

    sigdata = splitsig[1]
    if not nohashoid:
        if sigdata[:len(hash_oid)] != hash_oid:
            return False
        sigdata = sigdata[len(hash_oid):]

    return sigdata == hashdig


def xor32(data, key):
    res = ""
    for i, c in enumerate(data):
        res += chr((ord(c) ^ ord(key[i % 4])) & 0xFF)
    return res


class MemObj(object):
    def __init__(self, data):
        self.data = data
        self.offs = 0
        self.decrdata = ""

    def readByte(self):
        val = ord(self.data[self.offs])
        self.decrdata += self.data[self.offs]
        self.offs += 1
        return val

    def readBool(self):
        val = self.data[self.offs] != '\0'
        self.decrdata += '\x01' if val else '\0'
        self.offs += 1
        return val

    def readWord(self):
        val = struct.unpack("<H", self.data[self.offs:self.offs + 2])[0]
        self.decrdata += self.data[self.offs:self.offs + 2]
        self.offs += 2
        return val

    def readWordBE(self):
        val = struct.unpack(">H", self.data[self.offs:self.offs + 2])[0]
        self.decrdata += self.data[self.offs:self.offs + 2]
        self.offs += 2
        return val

    def readString(self):
        strsize = self.readWordBE()
        val = xor32(self.data[self.offs + 4:self.offs + strsize], self.data[self.offs:self.offs + 4])
        self.decrdata += "\0\0\0\0"
        self.decrdata += val
        self.offs += strsize
        return val

    def readData(self, size):
        val = self.data[self.offs:self.offs + size]
        self.decrdata += val
        self.offs += size
        return val

    def readSimpleUrl(self):
        # TODO: order of onget and onpost is unknown
        return Url(type=self.readBool(),
                   onget=self.readBool(),
                   onpost=self.readBool(),
                   pattern=self.readString())

    def readClickshotUrl(self):
        # TODO: order of onget/onpost and xrange/yrange is unknown
        return Url(type=self.readBool(),
                   onget=self.readBool(),
                   onpost=self.readBool(),
                   pattern=self.readString(),
                   clicks=self.readWordBE(),
                   xrange=self.readWordBE(),
                   yrange=self.readWordBE())


class Url(object):
    def __init__(self, type=None, onget=None, onpost=None, pattern=None, clicks=None, xrange=None, yrange=None, modifiers=None, contentType=None):
        self.type = type
        self.onget = onget
        self.onpost = onpost
        self.pattern = pattern
        self.clicks = clicks
        self.xrange = xrange
        self.yrange = yrange
        self.modifiers = modifiers
        self.contentType = contentType

    def __str__(self):
        entry = '<url type="%s"' % ('allow' if self.type else 'deny')
        if self.onget:
            entry += ' onget="1"'
        if self.onpost:
            entry += ' onpost="1"'
        if self.clicks is not None:
            entry += ' clicks="%s"' % self.clicks
        if self.xrange is not None:
            entry += ' xrange="%s"' % self.xrange
        if self.yrange is not None:
            entry += ' yrange="%s"' % self.yrange
        if self.modifiers is not None:
            entry += ' modifiers="%s"' % self.modifiers
        if self.contentType:  # ignore when empty
            entry += ' contentType="%s"' % self.contentType
        entry += '>%s</url>' % self.pattern
        return entry


class Settings(object):
    def __init__(self):
        self.httpshots = []
        self.httpinjblock = []
        self.httpblock = []
        self.formgrabber = []
        self.clickshots = []
        self.httpinjects = []
        self.redirects = []
        self.redirectsattrs = ""
        self.bot_tick_interval = None
        self.node_tick_interval = None
        self.smartcard = None
        self.dridexurls = []

    @staticmethod
    def genURLEntry(type, onget, onpost, pattern, clicks=None, xrange=None, yrange=None):
        entry = '<url type="%s"' % ('allow' if type else 'deny')
        if onget:
            entry += ' onget="1"'
        if onpost:
            entry += ' onpost="1"'
        if clicks is not None:
            entry += ' clicks="%s"' % clicks
        if xrange is not None:
            entry += ' xrange="%s"' % xrange
        if yrange is not None:
            entry += ' yrange="%s"' % yrange
        entry += '>%s</url>' % pattern
        return entry

    def addHttpShots(self, url):
        self.httpshots.append(url)

    def addHttpInjBlock(self, url):
        self.httpinjblock.append(url)

    def addFormGrabber(self, type, onget, onpost, pattern):
        self.formgrabber.append(self.genURLEntry(type, onget, onpost, pattern))

    def addClickShots(self, type, onget, onpost, pattern, clicks, xrange, yrange):
        self.clickshots.append(self.genURLEntry(type, onget, onpost, pattern, clicks, xrange, yrange))

    def addHttpInject(self, name, conds, actions):
        # TODO: try to extract dridex URLs from action replacement

        res = '<httpinject name="%s">\n    <conditions>\n' % name
        for url in conds:
            res += "      " + str(url) + "\n"
        res += "    </conditions>\n    <actions>\n"
        for (pattern, modifiers, replacement) in actions:
            res += ('      <modify>\n        <pattern modifiers="%s"><![CDATA[%s]]></pattern>\n      <replacement><![CDATA[%s]]></replacement>\n      </modify>\n'
                    % (modifiers, pattern, replacement))
        res += '    </actions>\n  </httpinject>'
        self.httpinjects.append(res)

    def addRedirect(self, name, vnc, socks, postfwd, timeout, scriptname, uri):
        self.dridexurls.append(uri)
        res = ('<redirect name="%s" vnc="%d" socks="%d" uri="%s" timeout="%d"'
               % (name, vnc, socks, uri, timeout))
        if postfwd:
            res += ' postfwd="1"'
        res += '>%s</redirect>' % scriptname
        self.redirects.append(res)

    def setRedirectsAttrs(self, switchoff, redir_param_name, delay_param_name):
        self.redirectsattrs = (' switchoff="%s" redir_param_name="%s" delay_param_name="%s"'
                               % (switchoff, redir_param_name, delay_param_name))

    def setSmartCard(self, vnc, socks, interval, uri, ref, pattern):
        self.dridexurls.append(uri)
        self.smartcard = (vnc, socks, interval, uri, ref, pattern)

    @staticmethod
    def tostr(name, entries, attrstr=None):
        res = "<%s%s>" % (name, attrstr or "")
        if entries:
            res += "\n  " + "\n  ".join(map(str, entries)) + "\n"
        res += "</%s>\n" % name
        return res

    def __str__(self):
        res = "<settings>\n"
        if self.bot_tick_interval is not None:
            res += '<bot_tick_interval>%d</bot_tick_interval>\n' % self.bot_tick_interval
        if self.node_tick_interval is not None:
            res += '<node_tick_interval>%d</node_tick_interval>\n' % self.node_tick_interval
        res += self.tostr("httpshots", self.httpshots)
        res += self.tostr("httpinjblock", self.httpinjblock)
        res += self.tostr("httpblock", self.httpblock)
        res += self.tostr("formgrabber", self.formgrabber)
        res += self.tostr("clickshots", self.clickshots)
        res += self.tostr("redirects", self.redirects, self.redirectsattrs)
        if self.smartcard:
            (vnc, socks, interval, uri, ref, pattern) = self.smartcard
            res += ('<smartcard vnc="%d" socks="%d" interval="%d" uri="%s" ref="%s"><![CDATA[%s]]></smartcard>\n'
                    % (vnc, socks, interval, uri, ref, pattern))
        res += self.tostr("httpinjects", self.httpinjects)
        res += "</settings>"
        return res


def get_tag(xmldata, tag):
    pos = 0
    tagstart = None
    while True:
        tagstart = xmldata.find("<" + tag, pos)
        if tagstart == -1:
            return (None, None)

        # Did we find the tag name with a proper delimiter?
        if xmldata[tagstart + 1 + len(tag)] in ['>', ' ', '\t']:
            break

        # No, we just got another tag starting with this tagname, search for next
        pos = tagstart + 1 + len(tag)

    tagcontent = ""
    tagattrs = {}

    curoffs = tagstart + 1 + len(tag)
    while curoffs < len(xmldata):
        ch = xmldata[curoffs]
        if ch == '/':
            if xmldata[curoffs + 1] == '>':
                break
            else:
                raise ValueError("Unexpected '/' in xml data")

        if ch == '>':
            tagend = xmldata.find("</" + tag + ">", curoffs + 1)
            if tagend == -1:
                raise ValueError('Missing closing tag for "%s"' % tag)
            tagcontent = xmldata[curoffs + 1:tagend]
            break

        if ch == ' ':
            curoffs += 1
        else:
            match = re.match(r'^(\w+)="([^"]*)"', xmldata[curoffs:])
            if not match:
                raise ValueError("Invalid XML attribute syntax at offset %d" % curoffs)

            tagattrs[match.group(1)] = match.group(2)
            curoffs += len(match.group(0))

    return (tagcontent, tagattrs)


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <xml settings response file>" % sys.argv[0])
        sys.exit(1)

    xmldata = open(sys.argv[1], "rb").read()

    (tagcontent, tagattrs) = get_tag(xmldata, "settings")
    if tagcontent is None:
        print("settings tag not found.")
        sys.exit(1)

    data = base64.b64decode(tagcontent)

    found = False
    for i in range(20):
        data = xor32(data[4:], data[:4])
        if rsa_verify(data[:0x80][::-1], data[0x80:], serverpublickey, 'sha1'):
            found = True
            print("Found after %d XOR decryptions." % i)
            break

    if not found:
        print("Sorry, unable to decrypt.")
        sys.exit(1)

    memobj = MemObj(data)
    memobj.readData(0x80)  # skip RSA SHA1 signature
    settings = Settings()

    while memobj.offs + 3 < len(memobj.data):
        elemtype = memobj.readByte()
        elemsize = memobj.readWordBE()

        # 1: httpshots
        if elemtype == 1:
            settings.httpshots.append(memobj.readSimpleUrl())

        # 2: formgrabber
        elif elemtype == 2:
            settings.formgrabber.append(memobj.readSimpleUrl())

        # 3: httpinjblock
        elif elemtype == 3:
            settings.httpinjblock.append(memobj.readSimpleUrl())
        
        # 4: unknown
        elif elemtype == 4:
            url = memobj.readSimpleUrl()
            str2 = memobj.readString()
            
            print("Unknown elemtype 4: %s + %s" % (url, str2))

        # 5: httpblock
        elif elemtype == 5:
            settings.httpblock.append(memobj.readSimpleUrl())

        # 6: clickshots
        elif elemtype == 6:
            settings.clickshots.append(memobj.readClickshotUrl())

        # 7: httpinjects
        elif elemtype == 7:
            name = memobj.readString()
            numConds = memobj.readWordBE()
            numActions = memobj.readWordBE()
            conds = []
            actions = []
            for i in range(numConds):
                url = memobj.readSimpleUrl()
                url.modifiers = memobj.readString()
                url.contentType = memobj.readString()
                conds.append(url)
            for i in range(numActions):
                pattern = memobj.readString()
                modifiers = memobj.readString()
                replacement = memobj.readString()
                actions.append((pattern, modifiers, replacement))

            settings.addHttpInject(name, conds, actions)

        # 8: redirects
        elif elemtype == 8:
            name = memobj.readString()
            vnc = memobj.readBool()
            socks = memobj.readBool()
            unk = memobj.readBool()
            timeout = memobj.readWordBE()
            scriptname = memobj.readString()
            uri = memobj.readString()

            settings.addRedirect(name, vnc, socks, unk, timeout, scriptname, uri)

        # 9: attributes of redirects element
        elif elemtype == 9:
            switchoff = memobj.readString()
            redir_param_name = memobj.readString()
            delay_param_name = memobj.readString()

            settings.setRedirectsAttrs(switchoff, redir_param_name, delay_param_name)

        # 10: bot_tick_interval
        elif elemtype == 10:
            settings.bot_tick_interval = memobj.readWordBE()
            unk = memobj.readWordBE()

            if unk != settings.bot_tick_interval:
                print("bot_tick_interval with two values: %d and %d" % (settings.bot_tick_interval, unk))

        # 11: node_tick_interval
        elif elemtype == 11:
            settings.node_tick_interval = memobj.readWordBE()
            unk = memobj.readWordBE()

            if unk != settings.node_tick_interval:
                print("node_tick_interval with two values: %d and %d" % (settings.node_tick_interval, unk))

        # 12: smartcard
        elif elemtype == 12:
            vnc = memobj.readBool()
            socks = memobj.readBool()
            interval = memobj.readWordBE()
            uri = memobj.readString()
            ref = memobj.readString()
            pattern = memobj.readString()

            settings.setSmartCard(vnc, socks, interval, uri, ref, pattern)

        # 14: unknown
        elif elemtype == 14:
            unk = memobj.readBool()

            print("Unknown element type 14: %s" % unk)

        else:
            print("Unknown element type %d" % elemtype)
            memobj.readData(elemsize)  # skip unknown element

    # Write decrypted serialized settings file
    with open(sys.argv[1] + ".decr", "wb") as f:
        f.write(memobj.decrdata)

    # Write readable XML version
    with open(sys.argv[1] + ".settings", "wb") as f:
        f.write(str(settings))

    print("\nFound possible Dridex URLs:\n" + "\n".join(settings.dridexurls))


if __name__ == "__main__":
    main()
