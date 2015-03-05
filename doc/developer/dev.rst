Run Docker container from image
###############################

Allowing self-signed certificates
=================================
To allow the Python lib `requests` (used by e.g. the MDX interface in pyoidc) to verify self-signed SSL certificates,
set the environment variable `REQUESTS_CA_BUNDLE` to the path to a `CA_BUNDLE` containing the CA certificate for the
self-signed certificate::

    docker run svs -e REQUESTS_CA_BUNDLE=ca-bundle.crt <..other params..>

The file `ca-bundle.crt` must be accessible inside the Docker container. This is easiest achieved by placing it in the
directory on the host which is mounted as a volume inside the Docker container (see :ref:`docker_image`).


Internationalization
####################

InAcademia uses the ``Babel`` distribution for internationalization (i18n).


When adding any new strings to the code wrap the message key with "gettext", e.g.::

    print gettext("error_general")

The initial messages was extracted using::

    python setup.py extract_messages --input-dirs src/svs --output-file src/svs/data/i18n/messages.pot

Updated .po file with new keys which has been added to the po template file::

    python setup.py update_catalog -l en -i src/svs/data/i18n/messages.pot -o src/svs/data/i18n/locales/en/LC_MESSAGES/messages.po

Generate .mo file::

    python setup.py compile_catalog --directory src/svs/data/i18n/locales/ --locale en

or using the custom command in setup.py (which specified the default directory for .po files in the project)::

    python setup.py compile_all_catalogs

This custom command is also integrated as a subcommand of ``./setup.py install``, which makes sure the .mo files are
automatically generated at install time.