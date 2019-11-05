
up:
	docker-compose up -d
	sleep 5
	VAULT_ADDR=http://localhost:8222 VAULT_TOKEN=toor vault status
	VAULT_ADDR=http://localhost:8222 VAULT_TOKEN=toor vault secrets enable transit
	VAULT_ADDR=http://localhost:8222 VAULT_TOKEN=toor vault write -f transit/keys/kubernetes
	docker-compose logs -f 

down:
	docker-compose down
