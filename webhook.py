import os
import json
import binascii

from twisted.internet import defer, reactor
from twisted.internet.task import LoopingCall
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import clientFromString
from twisted.web.server import Site

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from autobahn.twisted.component import run, Component
from autobahn.wamp.cryptobox import KeyRing, Key


import klein

# Storing our secrets in files to make the examples simpler; something
# like 'keyring' or 'vault' would be preferable
with open('secrets-onion', 'r') as f:
    onion_addr = f.read().strip()
with open('secrets-github', 'rb') as f:
    github_secret = f.read().strip()
with open('secrets-webhook-authkey', 'r') as f:
    webhook_auth_key = f.read()
keyring = KeyRing()  # for end-to-end encryption
with open('secrets-webhook-priv', 'rb') as priv:
    with open('secrets-builder-pub', 'rb') as pub:
        # we are the "originator" because we send publish events
        key = Key(
            originator_priv=priv.read().decode('ascii'),
            responder_pub=pub.read().decode('ascii'),
        )
        keyring.set_key(u'webhook.github.push', key)


# define our webhook component, configuring it as required, joining
# the realm "agent". The WebSocket will demand authentication (using
# "WAMP CryptoSign"), so we configure that as well.
hook = Component(
    transports=[
        {
            "endpoint": clientFromString(reactor, u'tor:{}:5000'.format(onion_addr)),
            "url": u"ws://{}:5000/".format(onion_addr),
        }
    ],
    realm=u"agent",
    authentication={
        u"cryptosign": {
            u"authid": u"agent",
            u"authrole": u"github",
            u"privkey": webhook_auth_key,
        }
    }
)


# some utility methods for our Klein Web Server
def _confirm_signature(sig, data):
    h = hmac.HMAC(github_secret, hashes.SHA1(), default_backend())
    h.update(data)
    our_sig = b'sha1=' + binascii.b2a_hex(h.finalize())
    return _constant_compare(our_sig, sig)


def _hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()


def _constant_compare(a, b):
    return _hmac_sha256(_nonce, a) == _hmac_sha256(_nonce, b)
_nonce = os.urandom(32)


# the "on_join" notification runs when the WAMP session has
# successfully connected, authenticated and hence joined a realm on
# the router.
@hook.on_join
@defer.inlineCallbacks
def join(session, details):
    print("joined: {}".format(details))
    session.set_payload_codec(keyring)  # e2e encryption keys

    # we create a Klein web site that listens for incoming TLS-secured
    # connections from GitHub, checks the signature and if it's valid
    # forwards the event through WAMP. The Crossbar.io "ReST Bridge"
    # can do this too, but we don't want our router on a public machine.
    app = klein.app.Klein()

    @app.route('/webhook/github', methods=['POST'])
    def github_webhook(request):
        raw_data = request.content.read()
        signature = str(request.requestHeaders.getRawHeaders(u'X-Hub-Signature')[0]).lower()
        signature = signature.encode('ascii')
        if _confirm_signature(signature, raw_data):
            data = json.loads(raw_data)
            kind = str(request.requestHeaders.getRawHeaders(u'X-GitHub-Event')[0]).lower()
            topic = u'webhook.github.{}'.format(kind)
            print("Publishing to: {}".format(topic))
            for k, v in data.items():
                print("  {}".format(k))
            if session:
                session.publish(topic, **data)
        else:
            raise Exception("signature confirmation failed")

    # activate our site; this uses txacme (the "le:" endpoint plugin)
    # and so will request (and keep renewing) a "Let's Encrypt" TLS
    # certificate for this domain keeping the keys in /tmp/certs
    site = Site(app.resource())
    ep = serverFromString(reactor, 'le:/tmp/certs:tcp:443')
    yield ep.listen(site)


if __name__ == '__main__':
    run([hook])
