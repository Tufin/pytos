===============================
=Tufin PS Scripts Installation=
===============================
1. Run the script at /opt/tufin/securitysuite/ps/setup_tufin_ps_scripts.sh as the root user.
2. When prompted, enter the credentials for systems the scripts will interact with (securetrack,securechange,smtp server,remedy server)
   To skip a section, hit Control+C.

To change the stored credentials, run the script located at /opt/tufin/securitysuite/ps/bin/set_secure_store.py:
	sudo -u tomcat /opt/tufin/securitysuite/ps/bin/set_secure_store.py -F

====================================
Pyton for Tufin Orchestration Suite
====================================

Pyton for Tufin Orchestration Suite provides easy connection to the RESTful APIs. You might find
it most useful for tasks involving <x> and also <y>. Typical usage
often looks like this::

    #!/usr/bin/env python

    from pytos.secureapp import Helpers
    from pytos.securechange import Helpers
    from pytos.securetrack import Helpers

    if utils.has_towel():
        print "Your towel is located:", location.where_is_my_towel()

(Note the double-colon and 4-space indent formatting above.)

Paragraphs are separated by blank lines. *Italics*, **bold**,
and ``monospace`` look like this.


A Section
=========

Lists look like this:

* First

* Second. Can be multiple lines
  but must be indented properly.

A Sub-Section
-------------

Numbered lists look like you'd expect:

1. hi there

2. must be going

Urls are http://like.this and links can be
written `like this <http://www.example.com/foo/bar>`_.