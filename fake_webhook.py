import os
import json
import binascii

from twisted.internet import defer, reactor
from twisted.internet.task import LoopingCall
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import clientFromString
from twisted.web.server import Site

from autobahn.twisted.component import run, Component
from autobahn.wamp.cryptobox import KeyRing, Key

# load our seekrit data

with open('secrets-onion', 'rb') as f:
    onion_addr = f.read().decode('ascii').strip()
with open('secrets-webhook-authkey', 'rb') as f:
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


# define a "fake" webhook component that will connect using the same
# credentials and methods as the "real" one, but will publish one fake
# "master" push event and exit.
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


# the "on_join" notification runs when the WAMP session has
# successfully connected, authenticated and hence joined a realm on
# the router.
@hook.on_join
@defer.inlineCallbacks
def join(session, details):
    print("joined: {}".format(details))
    session.set_payload_codec(keyring)  # e2e encryption keys

    topic = u'webhook.github.push'
    print("Publishing to: {}".format(topic))
    data = {
        "ref": "refs/heads/master",
        "commits": [
            {
                "id": "deadbeef",
                "message": "a commit message",
            }
        ]
    }
    yield session.publish(topic, **data)
    yield session.leave()


if __name__ == '__main__':
    run([hook])  #, log_level='debug')
