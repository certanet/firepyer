System Settings & Tasks
=======================

General system settings.

Config Import/Export
--------------------

.. py:currentmodule:: firepyer

.. class:: Fdm
   :noindex:

   .. automethod:: apply_config_import
   .. automethod:: delete_config_file
   .. automethod:: download_config_file
   .. automethod:: export_config
   .. fp_output:: export_config_params
   .. automethod:: get_config_files
   .. fp_output:: get_config_files
   
   .. automethod:: upload_config
   .. fp_output:: upload_config_params


General
-------

.. py:currentmodule:: firepyer

.. class:: Fdm
   :noindex:

   .. automethod:: create_syslog_server
   .. fp_output:: create_syslog_server_params
   .. automethod:: get_dhcp_servers
   .. fp_output:: get_dhcp_servers
   .. automethod:: get_hostname
   .. automethod:: get_syslog_servers
   .. fp_output:: get_syslog_servers
   .. automethod:: get_system_info
   .. fp_output:: get_system_info
   .. automethod:: send_command
   .. fp_output:: send_command_params
   .. automethod:: set_hostname


Updates
-------
Methods for updating various rule files

.. py:currentmodule:: firepyer

.. class:: Fdm
   :noindex:

   .. automethod:: update_intrusion_rules
   .. fp_output:: update_intrusion_rules
   .. automethod:: update_vdb
   .. automethod:: update_geolocation
   .. automethod:: upload_intrusion_rule_file
   .. automethod:: upload_geolocation_file
   .. automethod:: upload_vdb_file
   .. fp_output:: upload_vdb_file_params



Upgrades
--------
Methods for performing system upgrades

.. py:currentmodule:: firepyer

.. class:: Fdm
   :noindex:

   .. automethod:: get_upgrade_files
   .. fp_output:: get_upgrade_files
   .. automethod:: upload_upgrade


   perform_upgrade
