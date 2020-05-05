#!/usr/bin/python3
#
# Copyright 2018 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


"""Prepare metadata python module

The module is aimed to prepare system files (networking configs etc)
based on lab metadata.
Shell environment variables can be used in the metadata as Jinja2 variables.

Example:
  python prepare-metadata --metadata-file '/etc/lab-metadata.yaml'

Example of lab-metadata.yaml

'52:54:00:10:94:78':
  write_files:
  - path: '/tmp/123.yaml'
    content: |
      foo: bar
      bee: {{ PUBLIC_INTERFACE_IP }}

Attributes:
  metadata-file - The file with metadata
"""


__version__ = '1.0'

import argparse
import jinja2
import os
import yaml
import logging
import netifaces
import sys


LOG = logging.getLogger(__name__)


def main():
    logging.basicConfig(
        stream=sys.stdout,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    LOG.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        description=('Render system files based on metadata')
    )

    group = parser.add_argument_group()
    group.add_argument(
        '--metadata-file',
        help='The path to metadata file.',
        required=True
    )
    args = parser.parse_args()

    metadata = yaml.safe_load(render_template(args.metadata_file))

    if not metadata:
        LOG.info("The metadata is empty")
        return
    node_meta = get_node_metadata(metadata)
    if node_meta is not None:
        LOG.info(f"Processing node_metadata: {node_meta}")
        create_files(node_meta.get('write_files', []))
    else:
        LOG.error("No matches to MACs for node_metadata found")

def get_interface_mac(iface_name):
    mac = None
    ifaddresses = netifaces.ifaddresses(iface_name)
    link = ifaddresses.get(netifaces.AF_LINK, [])
    if link:
        return link[0]['addr']

def get_node_macs():
    ifaces = netifaces.interfaces()
    macs = [get_interface_mac(iface_name) for iface_name in ifaces]
    return [mac for mac in macs if mac is not None]

def get_node_metadata(metadata):
    for mac in get_node_macs():
        if mac in metadata:
             return metadata[mac]

def create_files(files_meta):
    for file_meta in files_meta:
        path = file_meta['path']
        content = file_meta['content']
        permissions = int(str(file_meta.get('permissions', '644')), base=8)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, permissions)

def render_template(file_path):
    """Render a Jinja2 template file

    In the template:
      {{ SOME_ENV_NAME }} : Insert an environment variable into the template

    :param file_path: str, path to the jinja2 template
    """
    LOG.info("Reading template {0}".format(file_path))

    path, filename = os.path.split(file_path)
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader([path, os.path.dirname(path)],
                                       followlinks=True))
    template = environment.get_template(filename).render(os.environ)

    return template

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        LOG.exception(f"Failed to apply image layout: {e}")
        sys.exit(1)
