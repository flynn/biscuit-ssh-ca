#!/usr/bin/env bash

set -e

[ "$DEBUG" == 'true' ] && set -x

DAEMON=sshd

echo "> Starting SSHD"

ls /etc/ssh/ssh_host_* >/dev/null 2>&1 || ssh-keygen -A

if [ -n "${SSH_USERS}" ]; then
    USERS=$(echo $SSH_USERS | tr "," "\n")
    for U in $USERS; do
        IFS=':' read -ra UA <<< "$U"
        _NAME=${UA[0]}
        _UID=${UA[1]}
        _GID=${UA[2]}
        if [ ${#UA[*]} -ge 4 ]; then
            _SHELL=${UA[3]}
        else
            _SHELL=''
        fi

        echo ">> Adding user ${_NAME} with uid: ${_UID}, gid: ${_GID}, shell: ${_SHELL:-<default>}."
        grep ${_NAME} /etc/group >/dev/null 2>&1 || groupadd -g ${_GID} ${_NAME}
        grep ${_NAME} /etc/passwd >/dev/null 2>&1 || useradd -r -m -p '' -u ${_UID} -g ${_GID} -s ${_SHELL:-""} -c 'SSHD User' ${_NAME}
    done
fi


stop() {
    echo "Received SIGINT or SIGTERM. Shutting down $DAEMON"
    # Get PID
    local pid=$(cat /var/run/$DAEMON/$DAEMON.pid)
    # Set TERM
    kill -SIGTERM "${pid}"
    # Wait for exit
    wait "${pid}"
    # All done.
    echo "Done."
}

echo "Running $@"
if [ "$(basename $1)" == "$DAEMON" ]; then
    trap stop SIGINT SIGTERM
    $@ &
    pid="$!"
    mkdir -p /var/run/$DAEMON && echo "${pid}" > /var/run/$DAEMON/$DAEMON.pid
    wait "${pid}"
    exit $?
else
    exec "$@"
fi
