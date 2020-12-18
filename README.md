# Biscuit SSH CA

## Packages

- [./pkg/antireplay](./pkg/antireplay): anti replay store and checker over biscuit signature nonces.
- [./pkg/authorization](./pkg/authorization): GRPC interceptors for client and server, handling biscuit transmission and validation.
- [./pkg/ca](./pkg/ca): GRPC client and server to issue SSH certificates.
- [./pkg/hubauth](./pkg/hubauth): hubauth authorization client providing a CLI compatible login flow.
- [./pkg/kmssign](./pkg/kmssign): duplicate of kms package of hubauth
- [./pkg/pb](./pkg/pb): protobuf service definition.

## Run the demo

### Start the CA service

```bash
export HUBAUTH_PUBLIC_KEY=SnmVZ8ucj0uiNhfFPgsfE1l1uc5k1TJ9WcWjNSRdcmQ= 
export AUDIENCE_NAME=https://controller.demo.localflynn.com 
export AUDIENCE_PUBLIC_KEY=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeSZhybggTIEKaKMJhG1uLPr6wdtdKcBkgs/FYfYzcS/4Soyg051ykT+VeKgmLnIi60qn9San05KJiuEjtF7RwQ== 
export CA_KMS_KEY_NAME=ca-key 
export FAKE_KMS=1 
go run cmd/hallowgcp-ext/main.go
```

This will start the server on port 8001 and print out the generated CA SSH public key, for example:

```
2020/12/18 16:20:20 CA SSH public key:
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJJZSQuw5oXSZq43vnxPkBpOIg4lCb8fKiYaDZwh1cgxCQW4C6GJDWO8fxyF7PZIgclGYPgT2vYP72P0pRe9eac= ca@hallowgpc
```

Having provided the FAKE_KMS env, this key is auto generated at startup and not kept. Keep it around, we'll need to provide it to the SSH server so it can verify user certificates in the next steps.

### Start the SSH server

A demo SSH server pre configured is provided in the [demo/sshd folder](./demo/sshd)

Build it with:

```bash
cd demo
docker build -t hallowgcp_sshd sshd/
```


Create the `demo/sshd/ca_key.pub` file with the CA SSH public key saved earlier (change to your own key):

```bash
echo "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJJZSQuw5oXSZq43vnxPkBpOIg4lCb8fKiYaDZwh1cgxCQW4C6GJDWO8fxyF7PZIgclGYPgT2vYP72P0pRe9eac= ca@hallowgpc" > sshd/ca_key.pub
```

Configure authorized principals:

```bash
echo "02lwamvv1ipchtq" > sshd/principals/developer
# ensure perms are correct
chmod 644 sshd/principals/developer
```

- `02lwamvv1ipchtq` must be a group assigned to your user
- `developer` is the target user we want to SSH into the host with.

We can now run the SSH server:

```bash
docker run -it --rm \
    -v $(pwd)/sshd/principals:/etc/ssh/principals \
    -v $(pwd)/sshd/ca_key.pub:/etc/ssh/ca_key.pub \
    -e "SSH_USERS=developer:1000:1000:/bin/bash" \
    hallowgcp_sshd:latest
```

### Generate a certificate and open SSH session
 
Now we can proceed as the end user, trying to log in the SSH server as `developer`
 
```bash
cd ../
go run cmd/cli/main.go \
    -audience https://controller.demo.localflynn.com \
    -auth-endpoint https://hubauth-ext-europe-west1-hlxlrkt3za-ew.a.run.app \
    -client-id EhEKBkNsaWVudBCAgIDo14eBCg \
    -local-redirect localhost:8888 \
    -ca-endpoint localhost:8001 \
    -principals 02lwamvv1ipchtq \
    developer@172.17.0.2
```

- `local-redirect` is an authorized redirect uri configured on the auth server
- `172.17.0.2` is the container IP of the SSH server, it may be different for you
- `-principals 02lwamvv1ipchtq` is a comma separated list of principals to add to the certificate.  
The *biscuit policies* on this audience will need to allow using thoses principals in order to allow the certificate generation.

A SSH session should now be opened on the target, if the biscuit policies of the authenticated user validated successfully and their requested principals are allowed by the SSH server.

# TODO

- by default, if no policies are defined on hubauth side, the service will allow generation for **any** principals, which is not great.  
we should probably define a way to reject biscuits not having any policy defined ?
- improve / cleanup / add missing logs and traces
- cloud run deployment
- see how to improve server config / client flags for better and simpler usage (mostly with audience / hubauth / keys)
- improve CLI flow to reuse existing certificate if still valid instead of regenerating all the time (+ leverage local SSH agent)
- anti replay store need a cleanup cron removing expired nonces.
