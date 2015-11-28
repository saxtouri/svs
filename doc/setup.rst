Setup InAcademia service node
#############################

In the following sections the installation, configuration and execution of the InAcademia service is described.

Installation
============

There are two ways to get the InAcademia software. The easiest way is to use the provided Docker image (see
:ref:`docker_image`) which contains all dependencies and will automatically spin up a new node as soon as it is started
as a Docker container. The software can also be installed manually (see :ref:`manual_install`).


.. _docker_image:

Docker image
------------

The Docker image should be used for deployment of the InAcademia service. It is not hosted on a public repository yet,
instead it is easiest to generate it from the Dockerfile in the separate git repository: `docker-svs`_).

To start a container from the image::

    docker run -d --name svs -v <host data dir>:<container data dir> -w <container data dir> [-p 8087:8087] \
        -e BASE=<base url of service> \
        -e MDX=<url of the (SAML) mdx service> \
        -e CDB=<url of the (OIDC) client db service> \
        -e DISCO=<url of the discovery service> \
        <image name>

The ``<host data dir>`` must have the following structure::

    <host data dir>
    ├── conf
    │   ├── logging_conf.json
    │   ├── op_config.json
    │   ├── sp_default.json
    │   ├── sp_persistent.json
    │   ├── sp_transient.json
    ├── inAcademia
    ├── inAcademia.pub
    ├── symkey.json

where ``inacademia*`` (in the root of the directory) is the signing/encryption key for the OpenID Connect OP and ``symkey.json`` is a symmetric key (in JWKS
format) to use for encrypting the SAML RelayState.

``docker compose``/``fig`` descriptors for the core service (svs) and auxiliary client MDQ server can be found at
 https://gist.github.com/rebeckag/447c70917c28dc4934bf

The running container can be stopped with ``docker stop svs``.

To start a container with a shell from the image, run ``docker run -it --entrypoint /bin/bash <image name>``.

.. _manual_install:

Manual installation
-------------------

*NOTE: The installation has only been tested on Mac OS X 10.9 and Debian based Linux distributions.*

    #) Clone the git repository: ``git clone https://github.com/its-dirg/svs.git [your path]``
    #) Install the dependencies: ``pip install -r requirements.txt``
    #) Install InAcademia using pip: ``pip install <path to dir containing setup.py>``


Configuration
=============

Three different parts of the InAcademia service can be configured:

    #) the logging: ``conf/logging_conf.json``
    #) the OpenID Connect Provider in the service: ``conf/op_config.json``
    #) the SAML SP's in the service: ``conf/sp_default.json``, ``conf/sp_transient.json``, ``conf/sp_persistent.json``

These files must be in the current working directory (and mounted in the Docker container, see :ref:`docker_image`).

Execution
=========

The InAcademia software supports the following options::

    usage: inacademia_server.py [-h] --mdx MDX --cdb CDB [--disco DISCO_URL] -b BASE
                 [-H HOST] [-p PORT]

    optional arguments:
      -h, --help         show this help message and exit
      --mdx MDX          base url to the MDX server
      --cdb CDB          base url to the client database server
      --disco DISCO_URL  base url to the discovery server
      -b BASE            base url for the service
      -H HOST            host for the service
      -p PORT            port for the service to listen on



.. _docker-svs: https://github.com/its-dirg/docker-svs
