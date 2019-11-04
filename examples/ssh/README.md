# SSH example



```shell

cd examples/ssh

vagrant up
export VAULT_ADDR=http://192.168.33.10:8200
export VAULT_TOKEN=toor
vault status

go run main.go
vagrant ssh --command /bin/bash -c "echo \"TrustedUserCAKeys /vagrant/ssh_key.pub\" | sudo tee --append /etc/ssh/sshd_config"
vagrant ssh --command /bin/bash -c "sudo systemctl restart sshd"
vault ssh -mode=ca -role=default -mount-point=ssh -public-key-path=~/.ssh/gpg.pub vagrant@192.168.33.10
```

## Cleanup

```shell

vagrant destroy

```
