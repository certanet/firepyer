Utilities
=========
A few general utilites for working with the API and it's objects, such as importing data from CSV files.

.. py:currentmodule:: firepyer.utils

.. autofunction:: read_objects_csv

.. fp_output:: read_objects_csv_params utils

.. code-block:: none
   :linenos:
   :caption: network_objects.csv

    name,value,type,description
    Host1-NIC1,10.0.1.1,host,HOST1-NIC1
    Host1-NIC2,10.0.1.2,host,HOST1-NIC2


.. autofunction:: read_groups_csv

.. fp_output:: read_groups_csv_params utils

.. code-block:: none
   :linenos:
   :caption: network_groups.csv

    name,objects,description
    GROUP-HOST1,Host1-NIC1,Host1
    GROUP-HOST1,Host1-NIC2,Host1
    GROUP-HOST2,Host2-NIC1,Host2
    GROUP-HOST2,Host2-NIC2,Host2
    GROUP-ALL-HOSTS,GROUP-HOST1,All hosts
    GROUP-ALL-HOSTS,GROUP-HOST2,All hosts




.. autofunction:: expand_merged_csv

.. fp_output:: expand_merged_csv_params utils

.. code-block:: none
   :linenos:
   :caption: raw_network_groups.csv

    name,objects,description
    GROUP-HOST1,Host1-NIC1,Host1
    ,Host1-NIC2,
    GROUP-HOST2,Host2-NIC1,Host2
    ,Host2-NIC2,
    GROUP-ALL-HOSTS,GROUP-HOST1,All hosts
    ,GROUP-HOST2,
