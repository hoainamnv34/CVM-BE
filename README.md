# Vulnerability management tool
Go (Golang) API REST Template/Boilerplate with Gin Framework

[![Go Report Card](https://goreportcard.com/badge/vulnerability-management)](https://goreportcard.com/report/vulnerability-management)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)
[![Build Status](https://travis-ci.com/antonioalfa22/vulnerability-management.svg?branch=master)](https://travis-ci.com/antonioalfa22/vulnerability-management)


## 1. Run with Docker

1. **Build**

```shell script
make build
docker build . -t api-rest
```

2. **Run**

```shell script
docker run -p 3000:3000 api-rest
```

3. **Test**

```shell script
go test -v ./test/...
```

_______

## 2. Generate Docs

```shell script
# Get swag
go get -u github.com/swaggo/swag/cmd/swag

# Generate docs
swag init --dir cmd/api --parseDependency --output docs
```

Run and go to **http://localhost:3000/docs/index.html**
