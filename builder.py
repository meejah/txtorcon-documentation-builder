import sys
import json
from os import environ
from os.path import join

from twisted.internet import defer, reactor
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.error import ProcessTerminated, ProcessExitedAlready, ProcessDone

from autobahn.twisted.component import run, Component
from autobahn.wamp.types import SubscribeOptions
from autobahn.wamp.cryptobox import KeyRing, Key


# Storing our secrets in files to make the examples simpler; something
# like 'keyring' or 'vault' would be preferable
keyring = KeyRing()
with open('secrets-builder-authkey', 'rb') as f:
    builder_auth_key = f.read()
with open('secrets-paths', 'rb') as f:
    basedir = f.read().strip().decode('ascii')
with open('secrets-builder-priv', 'rb') as priv:
    with open('secrets-webhook-pub', 'rb') as pub:
        # we are *receiving* events, so we're the responder
        key = Key(
            responder_priv=priv.read().decode('ascii'),  # webhook will encrypt to this
            originator_pub=pub.read().decode('ascii'),  # if we have to reply, encrypt to this
        )
        keyring.set_key(u'webhook.github.push', key)


# configure our component, connecting via a Unix socket locally and
# authenticating with 'cryptosign'
builder = Component(
    transports=[
        {
            u"url": u"ws://localhost/ws",
            u"endpoint": {
                "type": "unix",
                "path": "./.crossbar/sock"
            }
        }
    ],
    authentication={
        "cryptosign": {
            u"authid": u"builder",
            u"authrole": u"agent",
            u"privkey": builder_auth_key,
        }
    },
    realm=u"agent",
)


class _Task(ProcessProtocol):
    def __init__(self, all_done, launched, stdout=None, stderr=None):
        self._stderr = stderr
        self._stdout = stdout
        self._all_done = all_done
        self._launched = launched
        # some cutesy IProcessProtocol overrides
        if self._stderr is not None:
            self.outReceived = self._stderr.write
        if self._stdout is not None:
            self.errReceived = self._stdout.write

    def processEnded(self, reason):
        """IProcessProtocol API"""
        fail = reason.value
        is_fine = isinstance(fail, (ProcessDone, ProcessTerminated)) and \
                  fail.exitCode == 0

        for d in [self._launched, self._all_done]:
            if not d.called:
                if is_fine:
                    d.callback(None)
                else:
                    d.errback(fail)


@defer.inlineCallbacks
def _run(reactor, run_dir, program, *args):
    done = defer.Deferred()
    launched = defer.Deferred()
    proto = _Task(
        done, launched,
        # stdout=sys.stdout,
        stderr=sys.stderr,
    )

    print("running: {} {}".format(program, ' '.join(args)))
    transport = reactor.spawnProcess(
        proto, program,
        args=(program, ) + args,
        env=environ,
        path=run_dir,
    )
    yield done


@builder.subscribe(u'webhook.github.push')
@defer.inlineCallbacks
def _github_push(**kw):
    print("github push: {}".format(kw['ref']))
    print("  commits added:")
    for commit in kw['commits']:
        print("    {id}: {message}".format(**commit))

    if kw['ref'] != 'refs/heads/master':
        print("  not master; ignoring")
        return
    print("Rebuilding.")

    path = "{}/venv/bin:{}".format(basedir, environ.get('PATH', ''))
    environ['PATH'] = path
    from twisted.internet import reactor
    yield _run(reactor, join(basedir, u'git'), u'/usr/bin/git', u'pull')
    yield _run(reactor, join(basedir, u'git', u'docs'), '/usr/bin/make', 'html')
    print("github push processed successfully")


@builder.subscribe(u'webhook.github.', options=SubscribeOptions(match=u"prefix", details_arg="_details"))
def _github_notify(**kw):
    details = kw.pop("_details")
    print("{}: {} {}".format(details.topic, kw.get('created_at', ''), kw.get('state', '')))
    # print(kw.keys())



@builder.on_join
def joined(session, details):
    print("builder joined: {} {}".format(session, details))
    session.set_payload_codec(keyring)  # e2e encryption keys


if __name__ == '__main__':
    run([builder])
