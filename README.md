# Libvault

This abstraction library is meant to be used as a faster and more opinionated version of the 
standard `github.com/hashicorp/vault/api` default and supported Go SDK

This library is meant for people who wants to add Vault functionalities in their software 
without having to deal with all the plumbing necessary when using the default SDK

Testing vault integrations is not that hard but it's not trivial either, so we made an effort to 
deal with it so that you don't have to (as much)

Easy things should be easy

## Nota bene:
- Most of the interfaces used here are still compatible with the official SDK: this way if something is missing you can just continue using the other SDK to finish the job

## Usage

- [Kv](examples/kv/main.go)


## Testing

`go test ./...`

## Running vault locally

`docker run --rm -p8200:8200 vault:1.2.0 server -dev -dev-root-token-id=root`
