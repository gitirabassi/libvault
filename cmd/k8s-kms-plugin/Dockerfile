FROM golang:1.13 as BUILDER
RUN mkdir -p /go/kubernetes-vault-kms-plugin
COPY . /go/kubernetes-vault-kms-plugin
RUN cd /go/kubernetes-vault-kms-plugin && CGO_ENABLED=0 GOPROXY=https://proxy.golang.org go build -o /kubernetes-vault-kms-plugin

FROM alpine
COPY --from=BUILDER /kubernetes-vault-kms-plugin /kubernetes-vault-kms-plugin
RUN chmod +x /kubernetes-vault-kms-plugin
ENTRYPOINT ["/kubernetes-vault-kms-plugin"]



