Setup InAcademia service node
#############################

In the following sections the installation, configuration and execution of the InAcademia service is described.

Installation
============

There are two ways to get the InAcademia software. The simplest way is using the provided Docker image (see
:ref:`docker_image`) which contains all dependencies and will automatically spin up a new node as soon as it is started
as a Docker container. The software can also be installed manually (see :ref:`manual_install`).


.. _docker_image:

Docker image
------------

A Docker image exists and can be used for simple deployment of the InAcademia service (**this Docker image is not hosted
on a public repository yet, instead it is easiest to generate it from the Dockerfile** ``docker/Dockerfile`` **in the
code git repository, see** :ref:`manual_install` **for instructions on cloning the git repo**).

To start a container from the image::

    docker run -d --name svs -v <host data dir>:<container data dir> -w <container data dir> [-p 8087:8087] \
        -e BASE=<base url of service> \
        -e MDX=<url of the (SAML) mdx service> \
        -e CDB=<url of the (OIDC) client db service> \
        -e DISCO=<url of the discovery service> \
        <image name>

The ``<host data dir>` must have the following structure:

<host data dir>
├── conf
│   ├── logging_conf.json
│   ├── op_config.json
│   ├── sp_default.json
│   ├── sp_persistent.json
│   ├── sp_transient.json
├── inAcademia
├── inAcademia.pub
├── pki
│   ├── inacademia-test.crt
│   ├── inacademia-test.key
├── symkey.json

where ``inacademia*`` (in the root of the directory) is the signing/encyption key for the OpenID Connect OP,
``pki/`inacademia-test*` is the signing/encyption key for the SAML SP and ``symkey.json``is a symmetric key (in JWKS
format) to use for encrypting the SAML RelayState.

The running container can be stopped with ``docker stop svs``.

To start a container with a shell from the image, run `docker run -it --entrypoint /bin/bash <image name>`.

.. _manual_install:

Manual installation
-------------------

*NOTE: The installation has only been tested on Mac OS X 10.9 and Debian based Linux distributions.*

    #) Clone the git repository (you will need a ssh key, available from the InAcademia team): ``git clone git@git.nordu.net:inacademia.git [your path]``
    #) Install the dependencies: ``pip install -r requirements.txt``
    #) Install InAcademia using pip: ``pip install <path to dir containing setup.py>``


Configuration
=============

Three different parts of the InAcademia service can be configured:

    #) the logging: ``data/logging_conf.json``
    #) the OpenID Connect Provider in the service: ``data/op_config.json``
    #) the SAML SP's in the service: ``data/sp_default.json``, ``data/sp_transient.json``, ``data/sp_persistent.json``

Execution
=========

The InAcademia software supports the following options::

    usage: server.py [-h] --mdx MDX --cdb CDB -b BASE [-H HOST] [-p PORT]
                     (--disco DISCO_URL | --idp IDP_URL)

    optional arguments:
      -h, --help         show this help message and exit
      --mdx MDX          base url to the MDX server
      --cdb CDB          base url to the client database server
      -b BASE            base url for the service
      -H HOST            host for the service
      -p PORT            port for the service to listen on
      --disco DISCO_URL  base url to the discovery server
      --idp IDP_URL      base url to the discovery server

For testing, the auxiliary MDX servers for dynamic client info (cdb) and IdP metadata (mdx) can be started with the
supplied script ``bin/restart_mdx.sh``
