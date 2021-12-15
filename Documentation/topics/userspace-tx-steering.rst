..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

============================
Userspace Tx packet steering
============================

The userspace datapath supports three transmit packets steering modes.

Static mode
~~~~~~~~~~~

This mode is automatically selected when port's ``tx-steering`` option is set
to ``default`` or unset, and if the port's number of Tx queues is greater or
equal than the number of PMD threads.

This the recommended mode for performance reasons, as the Tx lock is not
acquired. If the number of Tx queues is greater than the number of PMDs, the
remaining Tx queues will not be used.

XPS mode
~~~~~~~~

This mode is automatically selected when port's ``tx-steering`` option is set
to ``default`` or unset, and if the port's number of Tx queues is lower than
the number of PMD threads.

This mode may have a performance impact, given the Tx lock acquisition is
required as several PMD threads may use the same Tx queue.

Hash mode
~~~~~~~~~

Hash-based Tx packets steering mode distributes the traffic on all the port's
transmit queues, whatever the number of PMD threads. Queue selection is based
on the 5-tuples hash already computed to build the flows batches, the selected
queue being the modulo between the hash and the number of Tx queues of the
port.

Hash mode may be used for example with Vhost-user ports, when the number of
vCPUs and queues of thevguest are greater than the number of PMD threads.
Without hash mode, the Tx queues used would bevlimited to the number of PMD.

Hash-based Tx packet steering may have an impact on the performance, given the
Tx lock acquisition is required and a second level of batching is performed.

This feature is disabled by default.

Usage
~~~~~

To enable hash mode::

    $ ovs-vsctl set Interface <iface> other_config:tx-steering=hash

To disable hash mode::

    $ ovs-vsctl set Interface <iface> other_config:tx-steering=default
