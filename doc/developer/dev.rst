Make Docker image
#################

Execute the following commands::

    # Copy the files from the inacademia repository, following the symlinks
    cp -L --remove-destination <inacademia repo path>/docker/* <dest_dir>

    cd <dest_dir>
    docker build -t svs .


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