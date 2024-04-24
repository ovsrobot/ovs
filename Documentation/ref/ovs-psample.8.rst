==========
ovs-sample
==========

Synopsis
========

``ovs-sample``
[``--group=``<group> | ``-g`` <group>]

``ovs-sample --help``

``ovs-sample --version``

Description
===========

Open vSwitch per-flow sampling can be configured to emit the samples
through the ``psample`` netlink multicast group.

Such sampled traffic contains, apart from the packet, some metadata that
gives further information about the packet sample. More specifically, OVS
inserts the ``observation_domain_id`` and the ``observation_point_id`` that
where provided in the sample action (see ``ovs-actions(7)``).

the ``ovs-sample`` program provides a simple way of joining the psample
multicast group and printing the sampled packets.


Options
=======

.. option:: ``-g`` <group> or ``--group`` <group>

  Tells ``ovs-sample`` to filter out samples that don't belong to that group.

  Different ``Flow_Sample_Collector_Set`` entries can be configured with
  different ``group_id`` values (see ``ovs-vswitchd.conf.db(5)``). This option
  helps focusing the output on the relevant samples.

.. option:: -h, --help

    Prints a brief help message to the console.

.. option:: -V, --version

    Prints version information to the console.
