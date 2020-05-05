=========================
OpenStack K8S Virtual Lab
=========================

Overview
--------

The repository contains utils (heat-templates) that aimed to deploy multinode
kubernetes cluster by Docker UCP on top of underlying OpenStack environment.
Further this inner openstack (openstack on k8s) might be deployed by following
instructions: https://docs.mirantis.com/mosk/beta

Configuration
-------------

* The repo provides the following list of environments that are stored in
``heat-templates/env/`` folder:

  * mstr3-wrkr3-cmp2-gtw0-lma3-osd3.yaml - is suitable for Neutron + OVS backend.
  * mstr3-wrkr3-cmp2-ntw3-lma3-osd3.yaml - is suitable for Neutron + TungstenFabric.

* Each environment contains set of settings. Before triggering deployment the following
parameters have to be set:

  * ``docker_ee_url`` link to repository that contains docker-ee packages
  * ``cluster_public_key`` SSH public key used for instances

* The underlying Openstack should have all needed resources like images, flavors.

* The underlying Openstack should have ability to disable portsecurity for VMs.

Installation
------------

.. code-block:: bash

  source keystone-openrc
  cd heat-templates
  export STACK_ENVIRONMENT=env/mstr3-wrkr3-cmp2-gtw0-lma3-osd3.yaml
  export STACK_NAME=demo-deployment
  openstack stack create -t top.yaml -e $STACK_ENVIRONMENT $STACK_NAME
