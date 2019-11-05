# PKI example

```shell

cd examples/pki

vagrant up vault
export VAULT_ADDR=http://192.168.33.10:8200
export VAULT_TOKEN=toor
vault status
vault secrets list
go run main.go

vagrant up etcd client

vagrant ssh client --command /bin/bash -c "etcdctl member list -w table && etcdctl endpoint status -w table"

```

## Cleanup

```shell

vagrant destroy -f

```


## Debugging


```shell
export VAULT_ADDR=http://192.168.33.10:8200
export VAULT_TOKEN=toor
vault write auth/approle/login role_id=@role_id secret_id=@secret_id
vault write cluster/staging/etcd/issue/server common_name=etcd-1
openssl x509 -noout -text -in /etc/etcd/pki/peer.crt
etcdctl --endpoints https://192.168.33.12:2379 --ca-file /etc/etcd/pki/ca.crt --key-file /etc/etcd/pki/peer.key --cert-file /etc/etcd/pki/peer.crt member list
etcdctl --endpoints https://192.168.33.12:2379 --ca-file /etc/etcd/pki/ca.crt --key-file /etc/etcd/pki/client.key --cert-file /etc/etcd/pki/client.crt member list
etcdctl --endpoints https://192.168.33.12:2379 --cacert /etc/etcd/pki/ca.crt --key /etc/etcd/pki/client.key --cert /etc/etcd/pki/client.crt member list
```
