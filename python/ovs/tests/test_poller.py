import os
import resource

from unittest import mock

import pytest

import ovs.poller


def test_poller_uses_poll_by_default():
    """Poller must use poll(2) when select.select is the real select(2).

    select(2) raises ValueError for a file descriptor numbered FD_SETSIZE
    (1024) or higher, poll(2) has no such limit.
    """
    with mock.patch.object(ovs.poller, '_using_eventlet_green_select',
                           return_value=False), \
            mock.patch.object(ovs.poller, 'gevent_monkey', None):
        assert isinstance(ovs.poller.Poller().poll, ovs.poller._PollPoll)


def test_poller_uses_select_under_eventlet():
    """Poller must keep emulating poll with select.select under eventlet.

    The green select has no FD_SETSIZE limit either and, unlike the real
    poll(2), it yields to the hub instead of blocking the interpreter.
    """
    with mock.patch.object(ovs.poller, '_using_eventlet_green_select',
                           return_value=True):
        assert isinstance(ovs.poller.Poller().poll, ovs.poller._SelectSelect)


def test_poller_uses_select_under_gevent():
    """Same as under eventlet, for a gevent patched select.select."""
    gevent_monkey = mock.Mock()
    gevent_monkey.is_object_patched.return_value = True
    with mock.patch.object(ovs.poller, '_using_eventlet_green_select',
                           return_value=False), \
            mock.patch.object(ovs.poller, 'gevent_monkey', gevent_monkey):
        assert isinstance(ovs.poller.Poller().poll, ovs.poller._SelectSelect)
    gevent_monkey.is_object_patched.assert_called_once_with('select',
                                                            'select')


@pytest.fixture
def pipe():
    rfd, wfd = os.pipe()
    yield rfd, wfd
    os.close(rfd)
    os.close(wfd)


def test_poll_accumulates_events(pipe):
    """Registering a fd again must add to its events, not replace them.

    The write end of an empty pipe is writable but never readable, so it
    only wakes up if POLLOUT survived the later registration for POLLIN.
    """
    _, wfd = pipe
    poll = ovs.poller._PollPoll()
    poll.register(wfd, ovs.poller.POLLOUT)
    poll.register(wfd, ovs.poller.POLLIN)
    assert poll.poll(0) == [(wfd, ovs.poller.POLLOUT)]


def test_poll_fd_above_fd_setsize(pipe):
    """poll(2) must handle a fd numbered FD_SETSIZE (1024) or higher."""
    fd = 1100
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft <= fd:
        pytest.skip("RLIMIT_NOFILE %d is too low" % soft)
    _, wfd = pipe
    os.dup2(wfd, fd)
    try:
        poll = ovs.poller._PollPoll()
        poll.register(fd, ovs.poller.POLLOUT)
        assert poll.poll(0) == [(fd, ovs.poller.POLLOUT)]
    finally:
        os.close(fd)
