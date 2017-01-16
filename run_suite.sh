#!/bin/bash -ex
CLI="lago"
DO_CLEANUP=false
RECOMMENDED_RAM_IN_MB=8196
EXTRA_SOURCES=()

usage () {
    echo "
Usage:

$0 [options] SUITE

This script runs a single suite of tests (a directory of tests repo)

Positional arguments:
    SUITE
        Path to directory that contains the suite to be executed

Optional arguments:
    -o,--output PATH
        Path where the new environment will be deployed.

    -e,--engine PATH
        Path to ovirt-engine appliance iso image

    -n,--node PATH
        Path to the ovirt node squashfs iso image

    -b,--boot-iso PATH
        Path to the boot iso for node creation

    -c,--cleanup
        Clean up any generated lago workdirs for the given suite, it will
        remove also from libvirt any domains if the current lago workdir fails
        to be destroyed

    -s,--extra-rpm-source
        Extra source for rpms, any string valid for repoman will do, you can
        specify this option several times. A common example:
            -s http://jenkins.ovirt.org/job/ovirt-engine_master_build-artifacts-el7-x86_64/123

        That will take the rpms generated by that job and use those instead of
        any that would come from the reposync-config.repo file. For more
        examples visit repoman.readthedocs.io

    -r,--reposync-config
        Use a custom reposync-config file, the default is SUITE/reposync-config.repo

"
}

ci_msg_if_fails() {
    msg_if_fails "Failed to prepare environment on step ${1}, please contact the CI team."
}

msg_if_fails() {
  # This text file will be passed back to gerrit
    local repo_root_dir=$(dirname $SUITE)
    echo "$1" > "${repo_root_dir}/failure_msg.txt"
}


del_failure_msg() {
    local repo_root_dir=$(dirname $SUITE)
    local msg_path="${repo_root_dir}/failure_msg.txt"
    [[ -e "$msg_path" ]] && rm "$msg_path"
}


env_init () {
    ci_msg_if_fails $FUNCNAME
    echo "#########################"
    local template_repo="${1:-$SUITE/template-repo.json}"
    local initfile="${2:-$SUITE/init.json}"
    $CLI init \
        $PREFIX \
        "$initfile" \
        --template-repo-path "$template_repo"
}


env_repo_setup () {
    ci_msg_if_fails $FUNCNAME
    echo "#########################"
    local extrasrc
    declare -a extrasrcs
    cd $PREFIX
    for extrasrc in "${EXTRA_SOURCES[@]}"; do
        extrasrcs+=("--custom-source=$extrasrc")
        echo "Adding extra source: $extrasrc"
    done
    local reposync_conf="$SUITE/reposync-config.repo"
    if [[ -e "$CUSTOM_REPOSYNC" ]]; then
        reposync_conf="$CUSTOM_REPOSYNC"
    fi
    echo "using reposync config file: $reposync_conf"
    http_proxy="" $CLI ovirt reposetup \
        --reposync-yum-config "$reposync_conf" \
        "${extrasrcs[@]}"
    cd -
}


env_start () {
    ci_msg_if_fails $FUNCNAME
    echo "#########################"
    cd $PREFIX
    $CLI start
    cd -
}


env_deploy () {
    ci_msg_if_fails "$FUNCNAME"
    echo "#########################"
    local res=0
    cd "$PREFIX"
    $CLI ovirt deploy || res=$?
    cd -
    return "$res"
}

env_status () {
    ci_msg_if_fails $FUNCNAME
    echo "#########################"
    cd $PREFIX
    $CLI status
    cd -
}


env_run_test () {
    msg_if_fails "Test ${1##*/} failed."
    echo "#########################"
    local res=0
    cd $PREFIX
    $CLI ovirt runtest $1 || res=$?
    cd -
    return "$res"
}

env_ansible () {
    ci_msg_if_fails $FUNCNAME
    echo "#########################"
    cd $PREFIX
    $CLI ansible_hosts > current/$ANSIBLE_HOSTS_FILE
    cd -

    # Ensure latest Ansible modules are tested:
    mkdir -p $SUITE/ovirt-deploy/library
    cd $SUITE/ovirt-deploy/library
    for module in vms disks clusters datacenters hosts networks quotas storage_domains templates vmpools nics
    do
      wget -N "https://raw.githubusercontent.com/ansible/ansible/devel/lib/ansible/modules/cloud/ovirt/ovirt_$module.py"
    done
    cd -

    # Until Ansible 2.3 is released we need to do this hack:
    path=$(rpm -ql ansible | grep "module_utils/ovirt.py$")
    wget https://raw.githubusercontent.com/ansible/ansible/devel/lib/ansible/module_utils/ovirt.py -O $path
}


env_collect () {
    local tests_out_dir="${1?}"
    echo "#########################"
    [[ -e "${tests_out_dir%/*}" ]] || mkdir -p "${tests_out_dir%/*}"
    cd "$PREFIX/current"
    $CLI collect --output "$tests_out_dir"
    cp -a "logs" "$tests_out_dir/lago_logs"
    cd -
}


env_cleanup() {
    echo "#########################"
    local res=0
    local uuid
    echo "======== Cleaning up"
    if [[ -e "$PREFIX" ]]; then
        echo "----------- Cleaning with lago"
        $CLI --workdir "$PREFIX" destroy --yes --all-prefixes \
        || res=$?
        echo "----------- Cleaning with lago done"
    elif [[ -e "$PREFIX/uuid" ]]; then
        uid="$(cat "$PREFIX/uuid")"
        uid="${uid:0:4}"
        res=1
    else
        echo "----------- No uuid found, cleaning up any lago-generated vms"
        res=1
    fi
    if [[ "$res" != "0" ]]; then
        echo "Lago cleanup did not work (that is ok), forcing libvirt"
        env_libvirt_cleanup "${SUITE##*/}" "$uid"
    fi
    echo "======== Cleanup done"
}


env_libvirt_cleanup() {
    local suite="${1?}"
    local uid="${2}"
    local domain
    local net
    if [[ "$uid" != "" ]]; then
        local domains=($( \
            virsh -c qemu:///system list --all --name \
            | egrep "$uid*" \
        ))
        local nets=($( \
            virsh -c qemu:///system net-list --all \
            | egrep "$uid*" \
            | awk '{print $1;}' \
        ))
    else
        local domains=($( \
            virsh -c qemu:///system list --all --name \
            | egrep "[[:alnum:]]*-lago-${suite}-" \
            | egrep -v "vdsm-ovirtmgmt" \
        ))
        local nets=($( \
            virsh -c qemu:///system net-list --all \
            | egrep "[[:alnum:]]{4}-.*" \
            | egrep -v "vdsm-ovirtmgmt" \
            | awk '{print $1;}' \
        ))
    fi
    echo "----------- Cleaning libvirt"
    for domain in "${domains[@]}"; do
        virsh -c qemu:///system destroy "$domain"
    done
    for net in "${nets[@]}"; do
        virsh -c qemu:///system net-destroy "$net"
    done
    echo "----------- Cleaning libvirt Done"
}


check_ram() {
    local recommended="${1:-$RECOMMENDED_RAM_IN_MB}"
    local cur_ram="$(free -m | grep Mem | awk '{print $2}')"
    if [[ "$cur_ram" -lt "$recommended" ]]; then
        echo "It's recommended to have at least ${recommended}MB of RAM" \
            "installed on the system to run the system tests, if you find" \
            "issues while running them, consider upgrading your system." \
            "(only detected ${cur_ram}MB installed)"
    fi
}


options=$( \
    getopt \
        -o ho:e:n:b:cs:r: \
        --long help,output:,engine:,node:,boot-iso:,cleanup \
        --long extra-rpm-source,reposync-config: \
        -n 'run_suite.sh' \
        -- "$@" \
)
if [[ "$?" != "0" ]]; then
    exit 1
fi
eval set -- "$options"

while true; do
    case $1 in
        -o|--output)
            PREFIX=$(realpath $2)
            shift 2
            ;;
        -n|--node)
            NODE_ISO=$(realpath $2)
            shift 2
            ;;
        -e|--engine)
            ENGINE_OVA=$(realpath $2)
            shift 2
            ;;
        -b|--boot-iso)
            BOOT_ISO=$(realpath $2)
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -c|--cleanup)
            DO_CLEANUP=true
            shift
            ;;
        -s|--extra-rpm-source)
            EXTRA_SOURCES+=("$2")
            shift 2
            ;;
	-r|--reposync-config)
	    readonly CUSTOM_REPOSYNC=$(realpath "$2")
	    shift 2
	    ;;
        --)
            shift
            break
            ;;
    esac
done

if [[ -z "$1" ]]; then
    echo "ERROR: no suite passed"
    usage
    exit 1
fi

export SUITE="$(realpath "$1")"
if [ -z "$PREFIX" ]; then
    export PREFIX="$PWD/deployment-${SUITE##*/}"
fi

if "$DO_CLEANUP"; then
    env_cleanup
    exit $?
fi

[[ -d "$SUITE" ]] \
|| {
    echo "Suite $SUITE not found or is not a dir"
    exit 1
}

echo "################# lago version"
lago --version
echo "#################"
check_ram "$RECOMMENDED_RAM_IN_MB"
echo "Running suite found in ${SUITE}"
echo "Environment will be deployed at ${PREFIX}"

rm -rf "${PREFIX}"

export PYTHONPATH="${PYTHONPATH}:${SUITE}"
source "${SUITE}/control.sh"

prep_suite "$ENGINE_OVA" "$NODE_ISO" "$BOOT_ISO"
run_suite
# No error has occurred, we can delete the error msg.
del_failure_msg
