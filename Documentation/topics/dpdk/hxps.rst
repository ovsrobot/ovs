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

=============================
Hash-based Tx packet steering
=============================

HXPS mode distributes the traffic on all the port transmit queues, whatever the
number of PMD threads. Queue selection is based on the 5-tuples hash already
computed to build the flows batches, the selected queue being the modulo
between the hash and the number of Tx queues of the port.

HXPS may be used for example with Vhost-user ports, when the number of vCPUs
and queues of the guest are greater than the number of PMD threads, aq without
HXPS, the Tx queues used would be limited to the number of PMD.

Hash-based Tx packet steering may have an impact on the performance, given the
Tx lock acquisition is required and a second level of batching is performed.

This feature is disabled by default.

Usage
~~~~~

To enable HXPS::

    $ ovs-vsctl set Interface <iface> other_config:hxps=true

To disable HXPS::

    $ ovs-vsctl set Interface <iface> other_config:hxps=false
