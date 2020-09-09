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

=================================
Userspace UDP performance tunning
=================================

This document describes how to tune UDP performance for Open vSwitch
userspace. In Open vSwitch userspace case, if you run iperf3 to test UDP
performance, you will see bigger packet loss rate, sometimes, you also
will see iperf3 outputs some information as below.

[  5]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   3.00-4.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   4.00-5.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   5.00-6.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   6.00-7.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   7.00-8.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   8.00-9.00   sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)
[  5]   9.00-10.00  sec  0.00 Bytes  0.00 bits/sec  0.018 ms  0/0 (-nan%)

or

iperf3: OUT OF ORDER - incoming packet = 70 and received packet = 97 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 71 and received packet = 97 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 72 and received packet = 99 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 14 and received packet = 123 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 15 and received packet = 125 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 78 and received packet = 137 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 79 and received packet = 137 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 80 and received packet = 139 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 82 and received packet = 172 AND SP = 5
iperf3: OUT OF ORDER - incoming packet = 83 and received packet = 173 AND SP = 5

There are many reasons resulting in such issues, for example, you don't use
-b to limit bandwidth, big packet(UDP packet data size is 8192 by default if
you don't use -l to specify UDP payload size) means many IP fragments if your
MTU is 1500/1450, any one of them is lost, that means the whole UDP packet
is lost because TCP/IP protocol stack can't reassemble original UDP packet, so
big packet isn't always good for performance. But among of them, the most
important reason is socket buffer size of UDP send side and receive side.

Here is iperf3 output if system interface added to OVS use default buffer size
(which is 212992 by default).

$ sudo ip netns exec ns03 iperf3 -t 10 -i 1 -u -b 10G -c 10.15.2.3 --get-server-output
Connecting to host 10.15.2.3, port 5201
[  4] local 10.15.2.7 port 39415 connected to 10.15.2.3 port 5201
[ ID] Interval           Transfer     Bandwidth       Total Datagrams
[  4]   0.00-1.00   sec   572 MBytes  4.79 Gbits/sec  73154
[  4]   1.00-2.00   sec   611 MBytes  5.12 Gbits/sec  78196
[  4]   2.00-3.00   sec   588 MBytes  4.93 Gbits/sec  75248
[  4]   3.00-4.00   sec   619 MBytes  5.19 Gbits/sec  79200
[  4]   4.00-5.00   sec   625 MBytes  5.24 Gbits/sec  79937
[  4]   5.00-6.00   sec   664 MBytes  5.57 Gbits/sec  85043
[  4]   6.00-7.00   sec   636 MBytes  5.34 Gbits/sec  81417
[  4]   7.00-8.00   sec   629 MBytes  5.27 Gbits/sec  80461
[  4]   8.00-9.00   sec   635 MBytes  5.33 Gbits/sec  81326
[  4]   9.00-10.00  sec   627 MBytes  5.26 Gbits/sec  80270
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bandwidth       Jitter    Lost/Total Datagrams
[  4]   0.00-10.00  sec  6.06 GBytes  5.21 Gbits/sec  0.067 ms  3793/5791 (65%)
[  4] Sent 5791 datagrams

Server output:
- - - - - - - -
Accepted connection from 10.15.2.7, port 54090
[  5] local 10.15.2.3 port 5201 connected to 10.15.2.7 port 39415
[ ID] Interval           Transfer     Bandwidth       Jitter    Lost/Total Datagrams
[  5]   0.00-1.00   sec  15.6 MBytes   131 Mbits/sec  0.067 ms  3793/5791 (65%)
[  5]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   3.00-4.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   4.00-5.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   5.00-6.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   6.00-7.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   7.00-8.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   8.00-9.00   sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)
[  5]   9.00-10.00  sec  0.00 Bytes  0.00 bits/sec  0.067 ms  0/0 (-nan%)


iperf Done.

Test setup is below:

  netns ns02                           netns ns03
+------------+                       +------------+
|10.15.2.3/24|                       |10.15.2.7/24|
|            |                       |            |
|   veth02   |                       |   veth03   |
+------|-----+  +-----------------+  +-----|------+
       |        |                 |        |
       +--------|       br0       |--------+
                |(datapath=netdev)|
                +-----------------+


But what if you increase socket buffer size? Let us increase it to 1073741823
and check it again.

$ sudo ip netns exec ns03 iperf3 -t 10 -i 1 -u -b 3G -c 10.15.2.3 --get-server-output
Connecting to host 10.15.2.3, port 5201
[  4] local 10.15.2.7 port 52686 connected to 10.15.2.3 port 5201
[ ID] Interval           Transfer     Bandwidth       Total Datagrams
[  4]   0.00-1.00   sec   343 MBytes  2.88 Gbits/sec  43945
[  4]   1.00-2.00   sec   357 MBytes  3.00 Gbits/sec  45742
[  4]   2.00-3.00   sec   357 MBytes  3.00 Gbits/sec  45759
[  4]   3.00-4.00   sec   357 MBytes  3.00 Gbits/sec  45716
[  4]   4.00-5.00   sec   358 MBytes  3.01 Gbits/sec  45882
[  4]   5.00-6.00   sec   360 MBytes  3.02 Gbits/sec  46046
[  4]   6.00-7.00   sec   368 MBytes  3.09 Gbits/sec  47163
[  4]   7.00-8.00   sec   357 MBytes  3.00 Gbits/sec  45734
[  4]   8.00-9.00   sec   353 MBytes  2.97 Gbits/sec  45246
[  4]   9.00-10.00  sec   356 MBytes  2.99 Gbits/sec  45630
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bandwidth       Jitter    Lost/Total Datagrams
[  4]   0.00-10.00  sec  3.49 GBytes  2.99 Gbits/sec  0.027 ms  0/456861 (0%)
[  4] Sent 456861 datagrams

Server output:
- - - - - - - -
Accepted connection from 10.15.2.7, port 54096
[  5] local 10.15.2.3 port 5201 connected to 10.15.2.7 port 52686
[ ID] Interval           Transfer     Bandwidth       Jitter    Lost/Total Datagrams
[  5]   0.00-1.00   sec   190 MBytes  1.59 Gbits/sec  0.031 ms  0/24303 (0%)
[  5]   1.00-2.00   sec   219 MBytes  1.84 Gbits/sec  0.023 ms  0/28025 (0%)
[  5]   2.00-3.00   sec   219 MBytes  1.84 Gbits/sec  0.029 ms  0/28006 (0%)
[  5]   3.00-4.00   sec   219 MBytes  1.83 Gbits/sec  0.030 ms  0/27990 (0%)
[  5]   4.00-5.00   sec   218 MBytes  1.83 Gbits/sec  0.031 ms  0/27920 (0%)
[  5]   5.00-6.00   sec   209 MBytes  1.76 Gbits/sec  0.094 ms  0/26807 (0%)
[  5]   6.00-7.00   sec   185 MBytes  1.55 Gbits/sec  0.032 ms  0/23673 (0%)
[  5]   7.00-8.00   sec   217 MBytes  1.82 Gbits/sec  0.030 ms  0/27721 (0%)
[  5]   8.00-9.00   sec   208 MBytes  1.75 Gbits/sec  0.029 ms  0/26646 (0%)
[  5]   9.00-10.00  sec   219 MBytes  1.84 Gbits/sec  0.029 ms  0/28007 (0%)
[  5]  10.00-11.00  sec   217 MBytes  1.82 Gbits/sec  0.026 ms  0/27816 (0%)
[  5]  11.00-12.00  sec   218 MBytes  1.83 Gbits/sec  0.024 ms  0/27936 (0%)
[  5]  12.00-13.00  sec   213 MBytes  1.79 Gbits/sec  0.036 ms  0/27282 (0%)
[  5]  13.00-14.00  sec   211 MBytes  1.77 Gbits/sec  0.035 ms  0/27018 (0%)
[  5]  14.00-15.00  sec   212 MBytes  1.78 Gbits/sec  0.029 ms  0/27162 (0%)
[  5]  15.00-16.00  sec   216 MBytes  1.81 Gbits/sec  0.025 ms  0/27605 (0%)


iperf Done.

You can see the performance number has huge improvement, packet loss rate
is 0.

.. note::

   This howto covers the steps required to tune UDP performance. The same
   approach can be used for iperf3 client and iperf3 server in VMs or network
   namespaces.

Tunning Steps
-------------

Perform the following steps on OVS node to tune socket buffer for OVS system
interface.

#. Change Linux system maximum socket buffer size for send and receive sides

       $ sudo sh -c "1073741823 > /proc/sys/net/core/wmem_max"
       $ sudo sh -c "1073741823 > /proc/sys/net/core/rmem_max"

   In order to ensure they are still set to the above value after your system
   is rebooted, you also need change systctl config to persist these values.

       $ sudo sh -c "echo net.core.rmem_max=1073741823 >> /etc/sysctl.conf"
       $ sudo sh -c "echo net.core.wmem_max=1073741823 >> /etc/sysctl.conf"

#. Change socket buffer size for OVS system interface

       $ sudo ovs-vsctl set Open_vSwitch . other_config:userspace-sock-buf-size=1073741823

   Note: You can set it to smaller value per your system, final recv socket
   buffer size for OVS system interface is minimum one of rmem_max and
   this value, final send socket buffer size for OVS system interface is
   minimum one of wmem_max and this value. So you can change it to the value
   you want just by changing other_config:userspace-sock-buf-size, you also
   can set other_config:userspace-sock-buf-size to 1073741823 and just change
   /proc/sys/net/core/rmem_max and /proc/sys/net/core/wmem_max to set the
   value you want, but the changed value will take effect only after you
   restart ovs-vswitchd no matter which one you prefer to use.

#. Restart ovs-vswitchd

   Note: The changed value will take effect only after you restart
   ovs-vswitchd.

#. You need repeat the above steps on all the OVS nodes to make sure
   cross-node veth-to-veth, veth-to-tap, or tap-to-tap UDP performance
   can get improved.

Potential Impact
----------------

Although this tunning can improve UDP performance, it possibly also
impacts on TCP performance, please reset the above values to default
values in your system if you see it hurts your TCP performance.
