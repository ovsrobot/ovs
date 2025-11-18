============
ovs-exporter
============

Synopsis
========

   ovs-exporter [-h] [-p <uint>] [-x] [-d] [-c [CONFIG]] [--unixctl]
                [--detach] [--no-chdir] [--monitor] [--pidfile [PIDFILE]] [--overwrite-pidfile]
                [--log-file [LOG_FILE]] [-v [VERBOSE ...]]

Description
===========

``ovs-exporter`` starts an HTTP server to export the OVS metrics.

This process is usually started using ``ovs-ctl start-ovs-exporter``, as it
will provide the required parameters for proper interfacing.

Options
=======

*  ``-p <uint>, --port <uint>``

  TCP port to listen on.

*  ``-x, --extended``

  Also export the extended metrics page

*  ``-d, --debug``

  Also export the debug metrics page

*  ``-c, --config [CONFIG]``

  Read configuration from file (default /etc/openvswitch/ovs-exporter.conf)

* ``--unixctl``

  Start a ``unixctl`` server in the process.
  This server allows the Open vSwitch scripts to interface with the process,
  for e.g. clean exit.

*  ``--detach``

  Run in background as a daemon.

*  ``--no-chdir``

  Do not chdir to '/'.

*  ``--monitor``

  Monitor ovs-exporter process.

*  ``--pidfile [PIDFILE]``

  Create pidfile (default /var/run/openvswitch/ovs-exporter.pid).

*  ``--overwrite-pidfile``

  With --pidfile, start even if already running.

*  ``--log-file [LOG_FILE]``

  Enables logging to a file. Default log file is used if LOG_FILE is omitted.

*  ``-v [VERBOSE ...], --verbose [VERBOSE ...]``

  Sets logging levels, see ovs-vswitchd(8). Defaults to dbg.

See Also
========

   /etc/openvswitch/ovs-exporter.conf

``ovs-metrics(8)``, ``ovs-vswitchd(8)``
