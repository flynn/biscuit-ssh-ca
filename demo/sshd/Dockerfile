FROM alpine:3.12

RUN apk update && \
    apk add bash openssh shadow && \
    rm -rf /var/cache/apk/*

EXPOSE 22

COPY entry.sh /entry.sh
COPY sshd_config /etc/ssh/sshd_config

ENTRYPOINT ["/entry.sh"]

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
