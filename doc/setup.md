# Setup InAcademia service node

In the following sections the installation, configuration and execution of the InAcademia service is described.

## Installation

There are two ways to get the InAcademia software. The easiest way is to use the
[Docker image](https://hub.docker.com/r/itsdirg/satosa) which contains all dependencies and will automatically spin up a
new node as soon as it is started as a Docker container. The software can also be installed manually, see below.


### Manual installation

*NOTE: The installation has only been tested on Mac OS X 10.9 and Debian based Linux distributions.*

* Clone the git repository: `git clone https://github.com/its-dirg/svs.git <your path>`
* Install InAcademia using pip: `pip install <your path>`


## Configuration
All necessary configuration is included in the `config` directory of this repository. InAcademia is based on the
SATOSA proxy, so documentation of all configuration options can be found in there.