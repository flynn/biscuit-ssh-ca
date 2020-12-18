# SSHD demo server

A container providing a SSH server configurable to authenticate users with SSH certificates.

## Build demo SSH server:

```bash
docker build -t hallowgcp_sshd sshd/
```

## Run the SSH server:

```bash
docker run -it --rm \
    -v $(pwd)/sshd/principals:/etc/ssh/principals \
    -v $(pwd)/sshd/ca_key.pub:/etc/ssh/ca_key.pub \
    -e "SSH_USERS=developer:1000:1000:/bin/bash" \
    hallowgcp_sshd:latest
```

### Volumes

- `$(pwd)/sshd/principals` is a folder, containing files named after existing system accounts (ie: root, www-data...).  
Each file may contains the principals allowed to login on this account.  
A user will be allowed to log in when those principals match thoses provided in his SSH certificate, under the `Principals` field.  
Certificate's principals can be inspected by using the `ssh-keygen -L -f id-cert.pub` command.
- `$(pwd)/sshd/ca_key.pub` is the CA SSH public key, used to verify the certificates signatures.

### Environments

- `SSH_USERS`: allows to provide extra users to create in the container, in the `username:uid:gid:shell` format.
- `DEBUG`: when set, will set -x on the entrypoint script.
