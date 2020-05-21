#!/bin/bash
set -x
# allow access to the local variables from prepare-metadata.py
set -a

#
# Variables in this block are passed from heat template
#
CONTROL_NETWORK_CIDR=$control_network_cidr
PUBLIC_INTERFACE=$private_floating_interface
PUBLIC_INTERFACE_IP=$private_floating_interface_ip
PUBLIC_INTERFACE_CIDR=$private_floating_network_cidr
PUBLIC_INTERFACE_NETMASK=$(echo ${PUBLIC_INTERFACE_CIDR} | cut -d'/' -f2)
STORAGE_BACKEND_INTERFACE=$storage_backend_interface
STORAGE_BACKEND_INTERFACE_IP=$storage_backend_network_interface_ip
STORAGE_BACKEND_NETWORK=$storage_backend_network_cidr
STORAGE_BACKEND_NETWORK_NETMASK=$(echo ${STORAGE_BACKEND_NETWORK} | cut -d'/' -f2)
STORAGE_FRONTEND_INTERFACE=$storage_frontend_interface
STORAGE_FRONTEND_INTERFACE_IP=$storage_frontend_network_interface_ip
STORAGE_FRONTEND_NETWORK=$storage_frontend_network_cidr
STORAGE_FRONTEND_NETWORK_NETMASK=$(echo ${STORAGE_FRONTEND_NETWORK} | cut -d'/' -f2)
NODE_TYPE=$node_type
UCP_MASTER_HOST=$ucp_master_host
NODE_METADATA='$node_metadata'
DOCKER_EE_URL='$docker_ee_url'
DOCKER_EE_RELEASE='$docker_ee_release'
FLOATING_NETWORK_PREFIXES=$private_floating_network_cidr
#
# End of block
#

DOCKER_DEFAULT_ADDRESS_POOL=${DOCKER_DEFAULT_ADDRESS_POOL:-10.10.1.0/16}
# DOCKER_DEFAULT_ADDRESS_SIZE have to be less then netmask in DOCKER_DEFAULT_ADDRESS_POOL because
# to the fact that actual netmask for docker_gwbridge is given from it
DOCKER_DEFAULT_ADDRESS_SIZE=${DOCKER_DEFAULT_ADDRESS_SIZE:-24}
DOCKER_EE_RELEASE=${DOCKER_EE_RELEASE:-stable-19.03}
DOCKER_EE_PACKAGES='docker-ee'
DOCKER_RELEASE='stable'
DOCKER_PACKAGES='docker-ce'
if [ -n "${DOCKER_EE_URL}" ]; then
    DOCKER_URL="${DOCKER_EE_URL}"
    DOCKER_RELEASE="${DOCKER_EE_RELEASE}"
    DOCKER_PACKAGES="${DOCKER_EE_PACKAGES}"
fi
CONTROL_NETWORK_CIDR=${CONTROL_NETWORK_CIDR:-"10.10.0.0/24"}
CONTROL_IP_ADDRESS=$(ip route get ${CONTROL_NETWORK_CIDR%/*} | head -n1 | fgrep -v ' via ' | awk '/ src / {print $6}')
PUBLIC_INTERFACE=${PUBLIC_INTERFACE:-ens4}
UCP_USERNAME=${UCP_USERNAME:-admin}
UCP_PASSWORD=${UCP_PASSWORD:-administrator}
OS_CODENAME=$(lsb_release -c -s)
KUBECTL_VERSION=${KUBECTL_VERSION:-v1.14.0}
NODE_DEPLOYMENT_RETRIES=${NODE_DEPLOYMENT_RETRIES:-15}
FLOATING_NETWORK_PREFIXES=${FLOATING_NETWORK_PREFIXES:-10.11.12.0/24}
PUBLIC_INTERFACE=${PUBLIC_INTERFACE:-ens4}
UCP_MASTER_HOST=${UCP_MASTER_HOST:-${CONTROL_IP_ADDRESS}}
UCP_IP_ADDRESS=${UCP_IP_ADDRESS:-$CONTROL_IP_ADDRESS}
NTP_SERVERS=${NTP_SERVERS:-"ldap.scc.mirantis.net ldap.bud.mirantis.net"}


function retry {
    local retries=$1
    shift
    local msg="$1"
    shift

    local count=0
    until "$@"; do
        exit=$?
        wait=$((2 ** $count))
        count=$(($count + 1))
        if [ $count -lt $retries ]; then
            echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
            sleep $wait
        else
            echo "Retry $count/$retries exited $exit, no more retries left."
            echo "$msg"
            return $exit
        fi
    done
    return 0
}

function wait_condition_send {
    local status=${1:-SUCCESS}
    local reason=${2:-\"empty\"}
    local data=${3:-\"empty\"}
    local data_binary="{\"status\": \"$status\", \"reason\": \"$reason\", \"data\": $data}"
    echo "Trying to send signal to wait condition 5 times: $data_binary"
    WAIT_CONDITION_NOTIFY_EXIT_CODE=2
    i=0
    while (( ${WAIT_CONDITION_NOTIFY_EXIT_CODE} != 0 && ${i} < 5 )); do
        $wait_condition_notify -k --data-binary "$data_binary" && WAIT_CONDITION_NOTIFY_EXIT_CODE=0 || WAIT_CONDITION_NOTIFY_EXIT_CODE=2
        i=$((i + 1))
        sleep 1
    done
    if (( ${WAIT_CONDITION_NOTIFY_EXIT_CODE} !=0 && "${status}" == "SUCCESS" ))
    then
        status="FAILURE"
        reason="Can't reach metadata service to report about SUCCESS."
    fi
    if [ "$status" == "FAILURE" ]; then
        exit 1
    fi
}


function configure_atop {
    sed -i 's/INTERVAL=600/INTERVAL=60/' /usr/share/atop/atop.daily
    systemctl restart atop
}

function install_required_packages {
    function install_retry {
        apt update
        export DEBIAN_FRONTEND=noninteractive; apt install -y apt-transport-https ca-certificates curl software-properties-common jq unzip atop iptables-persistent
    }
    retry 10 "Failed to install required packages" install_retry
}


function install_docker {
    function install_retry {
        curl --retry 6 --retry-delay 5 -fsSL "${DOCKER_URL}/gpg" | sudo apt-key add -
        add-apt-repository "deb [arch=amd64] ${DOCKER_URL}/ ${OS_CODENAME} ${DOCKER_RELEASE}"
        apt update
        apt install -y ${DOCKER_PACKAGES}
    }
    retry 10 "Failed to install docker" install_retry
}

function update_docker_network {
    mkdir -p /etc/docker
    cat <<EOF > /etc/docker/daemon.json
{
  "default-address-pools": [
    { "base": "${DOCKER_DEFAULT_ADDRESS_POOL}", "size": ${DOCKER_DEFAULT_ADDRESS_SIZE} }
  ]
}
EOF

}

function install_ucp {
    local tmpd
    tmpd=$(mktemp -d)
    cat <<EOF > ${tmpd}/docker_subscription.lic
$ucp_license_key
EOF
    function docker_run_retry {
        docker container run --rm --name ucp \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v $tmpd/docker_subscription.lic:/config/docker_subscription.lic \
        docker/ucp:3.2.4 install \
        --host-address $UCP_IP_ADDRESS \
        --admin-username $UCP_USERNAME \
        --admin-password $UCP_PASSWORD \
        --existing-config
    }

    retry 10 "Can't bring up docker UCP container" docker_run_retry
}

function download_bundles {
    local tmpd
    tmpd=$(mktemp -d)

    function download_bundles_retry {
    # Download the client certificate bundle
        curl --retry 6 --retry-delay 5 -k -H "Authorization: Bearer $AUTHTOKEN" https://${UCP_MASTER_HOST}/api/clientbundle -o ${tmpd}/bundle.zip
    }

    function get_authtoken_retry {
    # Download the bundle https://docs.docker.com/ee/ucp/user-access/cli/
    # Create an environment variable with the user security token
        AUTHTOKEN=$(curl --retry 6 --retry-delay 5 -sk -d '{"username":"'$UCP_USERNAME'","password":"'$UCP_PASSWORD'"}' https://${UCP_MASTER_HOST}/auth/login | jq -r .auth_token)
        if [ -z ${AUTHTOKEN} ]; then
            return -1
        fi
    }

    retry 10 "Can't get AUTHTOKEN from master." get_authtoken_retry
    retry 10 "Can't download bundle file from master." download_bundles_retry

    pushd $tmpd
    # Unzip the bundle.
    unzip bundle.zip

    # Run the utility script.
    eval "$(<env.sh)"
    mkdir -p /etc/kubernetes /root/.kube/
    cp kube.yml /etc/kubernetes/admin.conf
    cp kube.yml /root/.kube/config
    popd
}

function wait_for_node {
    function retry_wait {
        kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes |grep -w Ready |awk '{print $1}' |grep -q $(hostname)
    }
    retry $NODE_DEPLOYMENT_RETRIES "The node didn't come up." retry_wait
}

function join_node {
    local type=${1}
    function retry_join_node {
        env -i $(docker swarm join-token $type |grep 'docker swarm join' | xargs)
    }
    retry 10 "Failed to join node to swarm" retry_join_node
}

function create_ucp_config {
    echo "
[scheduling_configuration]
    enable_admin_ucp_scheduling = true
    default_node_orchestrator = \"kubernetes\"
" | docker config create com.docker.ucp.config -
}

function swarm_init {
    docker swarm init --advertise-addr ${UCP_IP_ADDRESS}
}

function rm_ucp_config {
    docker config rm com.docker.ucp.config
}

function install_kubectl {
    curl --retry 6 --retry-delay 5 -LO https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl
    chmod +x kubectl
    mv kubectl /usr/local/bin/
cat << EOF >> ~/.bashrc
source /usr/share/bash-completion/bash_completion
source <(kubectl completion bash)
EOF
}

function configure_ntp {
    cat << EOF > /etc/systemd/timesyncd.conf
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See timesyncd.conf(5) for details.

[Time]
NTP=${NTP_SERVERS}
#FallbackNTP=ntp.ubuntu.com
#RootDistanceMaxSec=5
#PollIntervalMinSec=32
#PollIntervalMaxSec=2048
EOF

    systemctl restart systemd-timesyncd
}

function prepare_network {
    if [ -z "${CONTROL_IP_ADDRESS}" ]; then
        wait_condition_send "FAILURE" "CONTROL_IP_ADDRESS is not found for the network ${CONTROL_NETWORK_CIDR}"
        exit 1
    fi

    systemctl restart systemd-resolved
    # Make sure local hostname is present in /etc/hosts
    sed -i "s/127.0.0.1 localhost/127.0.0.1 localhost\n${CONTROL_IP_ADDRESS} $(hostname)/" /etc/hosts

    configure_ntp
}

function workaround_default_forward_policy {
    cat << EOF > /etc/iptables/rules.v4
*filter
:DOCKER-USER - [0:0]
EOF
    for net in $FLOATING_NETWORK_PREFIXES; do
cat << EOF >> /etc/iptables/rules.v4
-A DOCKER-USER -d ${net} -j ACCEPT
-A DOCKER-USER -s ${net} -j ACCEPT
EOF
    done

cat << EOF >> /etc/iptables/rules.v4
-A DOCKER-USER -j RETURN
COMMIT
EOF
    sudo netfilter-persistent reload
}

function disable_rp_filter {
    # Run this func before "network_config" to create new interfaces with the default rp_filter value
    cat << EOF > /etc/sysctl.d/99-disable-rp-filter.conf
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
    sysctl -p /etc/sysctl.d/99-disable-rp-filter.conf
}

function network_config {
    PUBLIC_NODE_IP_ADDRESS=${PUBLIC_INTERFACE_IP:-$(ip addr show dev ${PUBLIC_INTERFACE} | grep -Po 'inet \K[\d.]+' | egrep -v "127.0.|172.17")}
    PUBLIC_NODE_IP_NETMASK=${PUBLIC_INTERFACE_NETMASK:-$(ip addr show dev ${PUBLIC_INTERFACE} | grep -Po 'inet \K[\d.]+\/[\d]+' | egrep -v "127.0.|172.17" | cut -d'/' -f2)}

    local public_interface=${1:-${PUBLIC_INTERFACE}}
    local cloud_netplan_cfg="/etc/netplan/50-cloud-init.yaml"
    local match_ip_line

    DEBIAN_FRONTEND=noninteractive apt -y install bridge-utils

cat << EOF > /etc/systemd/network/10-veth-phy-br.netdev
[NetDev]
Name=veth-phy
Kind=veth
[Peer]
Name=veth-br
EOF

    sed -i 's/.*ethernets:.*/&\n        veth-phy: {}/' ${cloud_netplan_cfg}
    sed -i 's/.*ethernets:.*/&\n        veth-br: {}/' ${cloud_netplan_cfg}

    match_ip_line=$(grep -nm1 "${PUBLIC_NODE_IP_ADDRESS}/${PUBLIC_NODE_IP_NETMASK}" ${cloud_netplan_cfg} | cut -d: -f1)

    sed -i "$((${match_ip_line}-1)),$((${match_ip_line}))d" ${cloud_netplan_cfg}

cat << EOF >> ${cloud_netplan_cfg}
    bridges:
        br-public:
            dhcp4: false
            interfaces:
            - ${PUBLIC_INTERFACE}
            - veth-br
            addresses:
            - ${PUBLIC_NODE_IP_ADDRESS}/${PUBLIC_NODE_IP_NETMASK}
EOF
    netplan --debug apply

    # NOTE(vsaienko): give some time to apply changes
    sleep 15
}

$functions_override

function set_node_labels {
    function set_node_labels_retry {
        kubectl patch node $(hostname) -p "{\"metadata\": ${NODE_METADATA}}"
    }
    retry 10 "Labeling node failed" set_node_labels_retry
}

HW_METADATA=''
# Place files specified in metadata to system.
# For example netplan.io metadata, the restart of services
# is not covered by script.
function prepare_metadata_files {
    /usr/sbin/prepare-metadata.py  --metadata-file /usr/share/metadata/lab-metadata.yaml
}

function collect_ceph_metadata {
    local ceph_osd_node
    ceph_osd_node=$(kubectl get nodes -l role=ceph-osd-node -o jsonpath={.items[?\(@.metadata.name==\"$(hostname)\"\)].metadata.name})

    if [[ -f /usr/share/metadata/ceph.yaml && ${ceph_osd_node} ]]; then
        HW_METADATA="{\"ceph\": {\"$(hostname)\": \"$(base64 -w 0 /usr/share/metadata/ceph.yaml)\"}}"
        ceph_store_drive=$(cat /usr/share/metadata/ceph.yaml | egrep '\- name\: vd?' | awk '{print $3}')
        if [[ -b /dev/${ceph_store_drive} ]]; then
            sgdisk --zap-all /dev/${ceph_store_drive}
        fi
    fi
}


case "$NODE_TYPE" in
    # Please keep the "prepare_metadata_files", "disable-rp-filter", "network_config" and "prepare_network" functions
    # at the very beginning in the same order.
    ucp)
        prepare_metadata_files
        disable_rp_filter
        network_config
        prepare_network
        update_docker_network
        install_required_packages
        configure_atop
        workaround_default_forward_policy
        install_docker
        swarm_init
        create_ucp_config
        install_ucp
        download_bundles
        rm_ucp_config
        install_kubectl
        wait_for_node
        set_node_labels
        collect_ceph_metadata
        ;;
    master)
        prepare_metadata_files
        disable_rp_filter
        network_config
        prepare_network
        update_docker_network
        install_required_packages
        configure_atop
        workaround_default_forward_policy
        install_docker
        download_bundles
        join_node manager
        install_kubectl
        wait_for_node
        set_node_labels
        collect_ceph_metadata
        ;;
    worker)
        prepare_metadata_files
        disable_rp_filter
        network_config
        prepare_network
        update_docker_network
        install_required_packages
        configure_atop
        workaround_default_forward_policy
        install_docker
        download_bundles
        join_node worker
        install_kubectl
        wait_for_node
        set_node_labels
        collect_ceph_metadata
        ;;
    spare)
        prepare_metadata_files
        disable_rp_filter
        network_config
        prepare_network
        update_docker_network
        install_required_packages
        configure_atop
        install_docker
        download_bundles
        workaround_default_forward_policy
        ;;
    *)
        echo "Usage: $0 {ucp|master|worker}"
        exit 1
esac


wait_condition_send "SUCCESS" "Instance successfuly started." "${HW_METADATA}"
