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

===========
ovs-flowviz
===========

Synopsis
========

``ovs-flowviz``
[``[-i | --input] <[alias,]file>``]
[``[-c | --config] <file>``]
[``[-f | --filter] <filter>``]
[``[-h | --highlight] <filter>``]
[``--style <style>``]
*<flow_type>* *<format>* [<arg>...]

``ovs-flowviz --help``

Description
===========

The ``ovs-flowviz`` program helps visualize OpenFlow and datapath flow dumps
in different formats in order to make them more easily understood.

The program works by reading flows from ``stdin`` or from a file specified
in the ``--input`` option, filtering them, highlighting them, and finally
outputting them in one of the predefined formats.


Options
=======

.. program: ovs-flowviz

.. option:: -h, --help

    Prints a brief help message to the console.

.. option:: -i <[alias,]file>, --input <[alias,]file>

    Specifies the file to read flows from. If not provided, ``ovs-flowviz``
    will read flows from stdin.

    This option can be specified multiple times.
    The file path can prepended by an alias that will be shown in the output.
    For example: ``--input node1,/path/to/file1 --input node2,/path/to/file2``

.. option:: -c <file>, --config <file>

    Specifies the style configuration file to use. ``ovs-flowviz`` ships with
    a default configuration file but it can be overridden using this option.
    Styles defined in the style configuration file will be select-able using
    the ``--style`` option.

    For more details on the style configuration file, see
    `Style Configuration File`_ section below.

.. option:: -f <filter>, --filter <filter>

   Tells ``ovs-flowviz`` to filter the flows and only show the ones that match
   the expression (although some formats implement filtering differently,
   see `Datapath tree format`_ below).

   The filtering syntax is detailed in `Filtering Syntax`_.

.. option:: -h <filter>, --highlight <filter>

   Tells ``ovs-flowviz`` to highlight the flows that match the provided filter

   The filtering syntax is detailed in `Filtering Syntax`_.

.. option:: --style <style>

   Specifies the style to use. The style must have been defined in the
   style configuration file.

.. option:: <flow_type>

   "openflow" or "datapath".

.. option:: <format>

   See `Supported formats`_ section.


Supported formats
=================

``ovs-flowviz`` supports several visualization formats for both OpenFlow and
datapath flows that are summarized in the following table:

.. list-table::
   :widths: 20 10 70
   :align: center
   :header-rows: 1

   * - Flow Type
     - Format
     - Description
   * - Both
     - console
     - Prints the flows in a configurable, colorful style in the console.
   * - Both
     - json
     - Prints the flows in JSON format.
   * - Both
     - html
     - Prints the flows in an HTML list.
   * - Openflow
     - cookie
     - Prints the flows in the console sorted by cookie.
   * - Openflow
     - logic
     - Prints the logical structure of flows in the console.
   * - Datapath
     - tree
     - Prints the flows a tree structure arranged by `recirc_id`.
   * - Datapath
     - graph
     - Prints a graphviz graph of the flows arranged by `recirc_id`.


Console format
~~~~~~~~~~~~~~

The ``console`` works for both OpenFlow and datapath flow types and prints
flows in the terminal with the style determined by the ``--style`` option.

Additionally, it accepts the following arguments:

.. option:: -h, --heat-map

   This option changes the color of the packet and byte counters to reflect
   their relative size. The color gradient goes through the following colors:
   blue (coldest, lowest), cyan, green, yellow, red (hottest, highest)

   Note filtering is applied before the range is calculated.


JSON format
~~~~~~~~~~~

The ``json`` format works for both OpenFlow and datapath flow types and prints
flows in JSON format. See `JSON Syntax`_ for more details.


HTML format
~~~~~~~~~~~

The ``html`` format works for both OpenFlow and datapath flows and prints
flows in an HTML table that offers some basic interactivity. OpenFlow flows
are sorted in tables and datapath flows are arranged in flow trees
(see `Datapath tree format`_ for more details).

Styles defined via Style Configuration File and selected via ``--style`` option
also apply to ``html`` format.


OpenFlow cookie format
~~~~~~~~~~~~~~~~~~~~~~

The OpenFlow ``cookie`` format is similar to the ``console`` format but
instead of arranging the flows per table, it arranges the flows per cookie.


Openflow logic format
~~~~~~~~~~~~~~~~~~~~~

The OpenFlow ``logic`` format helps visualize the logic structure of OpenFlow
pipelines by arranging flows into *logical blocks*.
A logical block is a set of flows that have:

* Same ``priority``.
* Match on the same fields (regardless of the match value and mask).
* Execute the same actions (regardless of the actions' arguments,
  except for resubmit and output).
* Optionally, the ``cookie`` can be counted as part of the logical flow.

This format supports the following extra arguments:

.. option:: -s, --show-flows

    Show all the flows under each logical block.

.. option:: -d, --ovn-detrace

    Use ovn-detrace.py script to extract cookie information (implies '-c').

.. option:: -c, --cookie

    Consider the cookie in the logical block.

.. option:: --ovn-detrace-path <path>

    Use an alternative path to look for ovn_detrace.py script.

.. option:: --ovnnb-db text

   Specify the OVN NB database string (implies '-d').
   Default value is "unix:/var/run/ovn/ovnnb_db.sock".

.. option:: --ovnsb-db text

   Specify the OVN SB database string (implies '-d').
   Default value is "unix:/var/run/ovn/ovnsb_db.sock".

.. option:: --o <text>, --ovn-filter <text>

   Specify the a filter to be run on the ovn-detrace information.
   Syntax: python regular expression
   (See https://docs.python.org/3/library/re.html).

.. option:: -h, --heat-map

   This option changes the color of the packet and byte counters to reflect
   their relative size. The color gradient goes through the following colors:
   blue (coldest, lowest), cyan, green, yellow, red (hottest, highest)

   Note filtering is applied before the range is calculated.


Datapath tree format
~~~~~~~~~~~~~~~~~~~~

The datapath ``tree`` format arranges datapath flows in a hierarchical tree
based on `recirc_id`. At the first level, flows with `recirc_id(0)` are
listed. If a flow contains a `recirc()` action with a specific `recirc_id`,
flows matching on that `recirc_id` are listed below. This is done recursively
for all actions.

The result is a hierarchical representation that helps understand how actions
are related to each other via recirculation. Note flows with a specific
non-zero `recirc_id` are listed below each flow that has a corresponding
`recirc()` action. Therefore, they would be duplicated leading to a longer
output.

Also, filtering works in a slightly different way for datapath flow trees.
Unlike other formats where a filter simply removes non-matching flows,
the output of a filtered datapath flow tree will show full sub-trees
that contain at least one flow that satisfies the filter.

The ``html`` format prints this same tree in an interactive HTML table.


Datapath graph format
~~~~~~~~~~~~~~~~~~~~~

The datapath ``graph`` generates a graphviz visual representation of the
same tree-like flow hierarchy that the ``tree`` format prints.

It supports the following extra argument:

.. option:: -h, --html

    Prints the graphviz format in an svg image alongside the interactive HTML
    table of flows (that 'html' format would print).


JSON Syntax
===========

Both OpenFlow and datapath `json` formats print a JSON list of JSON
objects each of one representing an individual flow.

Each flow object contains the following keys:

**orig**
    Contains the original flow string.


**info**
   Contains an object with the flow information
   such as: cookie, duration, table, n_packets, n_bytes, etc.


**match**
   Contains an object with the flow match.
   For each match, the object contains a key-value where the key is the name
   of the match as defined in ovs-fields and ovs-ofctl and the value
   represents the match value. The way each value is represented depends on its
   type. See `Value representation`_.


**actions**
   Contains a list of action objects.
   Each action is represented by an JSON object that has one key and one value.
   The key corresponds to the action name. The value represents the arguments
   of such key. See `Action representation`_.


**ufid**
   (datapath flows only) Contains the ufid.


Value representation
~~~~~~~~~~~~~~~~~~~~

Values are represented differently depending on their type:

* Flags: Fields that represent flags (e.g: tcp) are represented by boolean
  "true"

* Decimal / Hexadecimal: They are represented by their integer value.
  If they support masking, they are represented by a dictionary with two keys:
  value contains the field value and mask contains the mask. Both are integers.

* Ethernet: They are represented by a string: {address}[/{mask}]

* IPv4 / IPv6: They are represented by a string {address}[/mask]

* Registers: They are represented by a dictionary with three keys:
  field contains the field value (string), start and end that represent the
  first and last bit of the register.

For example, the register
::


   NXM_NX_REG10[0..15]


is represented as
::


   {
       "field": "NXM_NX_REG10",
       "start": 0,
       "end": 15
   },


Action representation
~~~~~~~~~~~~~~~~~~~~~

Actions are generally represented by an object that has a single key and a
value. The key is the action name as defined ovs-actions.

The value of actions that have no arguments (such as ``drop``) is
(boolean) ``true``.

The value of actions that have a list of arguments (e.g:
``resubmit([port],[table],[ct])``) is an object that has the name of the
argument as key. The argument names for each action is defined in
ovs-actions. For example, the action
::

   resubmit(,10)

is represented as
::

   {
       "redirect": {
           "port": "",
           "table": 10
       }
   }

The value of actions that have a key-word list as arguments
(e.g: ``ct([argument])``) is an object whose keys correspond to the keys
defined in ``ovs-actions(7)``. The way values are represented depends
on the type of the argument.
For example, the action
::

   ct(table=14,zone=NXM_NX_REG12[0..15],nat)

is represented as
::

   {
       "ct": {
           "table": 14,
           "zone": {
               "field": "NXM_NX_REG12",
               "start": 0,
               "end": 15
           },
           "nat": true
       }
   }


Style Configuration File
========================

The style configuration file that can be selected via the ``--config`` option
has INI syntax and can define any number of styles to be used by both
``console`` and ``html`` formats. Once defined in the configuration file
they can be selected using the ``--style`` option.

INI sections are used to define styles, ``[styles.mystyle]`` defines a style
called `mystle`. Within a section styles can be defined as:

::

     [FORMAT].[PORTION].[SELECTOR].[ELEMENT] = [VALUE]


**FORMAT**
   Either ``console`` or ``html``

**PORTION**
   The part of the a key-value the style applies to. It can be:
   ``key`` (to indicate the key part of a key-value), ``value`` (to indicate
   the value part of a key-value), ``flag`` (to indicate a single flag)
   or ``delim`` (to indicate delimiters such as parentheses, brackets, etc).

**SELECTOR**
   Is used to select what key-value the style applies to. It can be:
   ``highlighted`` (to indicate highlighted key-values), ``type.<type>``
   to indicate certain types such as `IPAddress` or `EthMask` or `<keyname>`
   to select a particular key name.

**ELEMENT**
   Is used to select what style element to modify. It can be one
   of: **color** or **underline** (only for **console** format).

**VALUE**
   Is either a color hex, other color names defined in the rich python
   library (https://rich.readthedocs.io/en/stable/appendix/colors.html) or
   "true" if the element is ``underline``.

A default configuration file is shipped with the tool and its path is printed
in the ``--help`` output. A detailed description of the syntax alongside
some examples are available there.


Filtering syntax
================

``ovs-flowviz`` provides rich highlighting and filtering. The special command
``ovs-flowviz filter`` dumps the filtering syntax:

::

    $ ovs-flowviz filter
    Filter Syntax
    *************

       [! | not ] {key}[[.subkey]...] [OPERATOR] {value})] [LOGICAL OPERATOR] ...

      Comparison operators are:
          =   equality
          <   less than
          >   more than
          ~=  masking (valid for IP and Ethernet fields)

      Logical operators are:
          !{expr}:  NOT
          {expr} && {expr}: AND
          {expr} || {expr}: OR

      Matches and flow metadata:
          To compare against a match or info field, use the field directly, e.g:
              priority=100
              n_bytes>10
          Use simple keywords for flags:
              tcp and ip_src=192.168.1.1

      Actions:
          Actions values might be dictionaries, use subkeys to access individual
          values, e.g:
              output.port=3
          Use simple keywords for flags
              drop

      Examples of valid filters.
          nw_addr~=192.168.1.1 && (tcp_dst=80 || tcp_dst=443)
          arp=true && !arp_tsa=192.168.1.1
          n_bytes>0 && drop=true


Example expressions:
::

   n_bytes > 0 and drop
   nw_src~=192.168.1.1 or arp.tsa=192.168.1.1
   ! tcp && output.port=2


Examples
========

Print OpenFlow flows sorted by cookie adding OVN data to each one:
::

    $ ovs-flowviz -i flows.txt openflow cookie --ovn-detrace

Print OpenFlow logical structure, showing the flows and heat-map:
::

    $ ovs-flowviz -i flows.txt openflow logic --show-flows --heat-map

Display OpenFlow flows in HTML format with "light" style and highlight drops:
::

    $ ovs-flowviz -i flows.txt --style "light" --highlight "n_packets > 0 and drop" openflow html > flows.html

Display the datapath flows in an interactive graphviz + HTML view:
::

    $ ovs-flowviz -i flows.txt datapath graph --html > flows.html

Display the datapath flow trees that lead to packets being sent to port 10:
::

    $ ovs-flowviz -i flows.txt --filter "output.port=10" datapath tree
