get-docs:
	go install github.com/swaggo/swag/cmd/swag@v1.8.4

swag:
	swag init --parseDependency  --parseInternal --parseDepth 100  -g main.go
	swag fmt	

build:
	@make swag
	go build -o bin/restapi main.go

run:
	@make swag
	go run main.go

test:
	go test -v ./test/...

build-docker: build
	@make swag
	docker build . -t hoainamnv34/cvm-be:0.0.1

run-docker: build-docker
	@make swag
	docker run -p 3000:3000 api-rest

tidy: ##- (opt) Tidy our go.sum file.
	go mod tidy


DB_CONTAINER_NAME=postgres
DB_NAME=vul_manager
DB_USER=root
DB_URL=postgresql://root:secret@localhost:5432/$(DB_NAME)?sslmode=disable

postgres: ## port 5432
	docker run -v ./postgres-data:/var/lib/postgresql/data --name $(DB_CONTAINER_NAME) --network host -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -d postgres:12-alpine

pgadmin: ## port 80
	docker run  --name pgadmin --network host -e PGADMIN_DEFAULT_EMAIL=name@example.com -e PGADMIN_DEFAULT_PASSWORD=admin -d dpage/pgadmin4:latest 

rm_container:
	docker stop $(DB_CONTAINER_NAME)
	docker stop pgadmin

createdb:
	docker exec -it $(DB_CONTAINER_NAME) createdb --username=root --owner=root $(DB_NAME)

migrate_up:
	docker run -v $(PWD)/db/migration:/migrations --network host migrate/migrate -path=/migrations/ -database "$(DB_URL)" -verbose up

migrate_up1:
	docker run -v $(PWD)/db/migration:/migrations --network host migrate/migrate -path=/migrations/ -database "$(DB_URL)" -verbose up 1

migrate_down:
	docker run -v $(PWD)/db/migration:/migrations --network host migrate/migrate -path=/migrations/ -database "$(DB_URL)" -verbose down

migrate_down1:
	docker run -v $(PWD)/db/migration:/migrations --network host migrate/migrate -path=/migrations/ -database "$(DB_URL)" -verbose down 1

new_migration:
	docker run -v $(PWD)/db/migration:/migrations --user $$(id -u):$$(id -g) --network host migrate/migrate create -ext sql -dir /migrations -seq $(name)
	
dropdb:
	docker exec -it postgres dropdb $(DB_NAME)


.PHONY: swag build run test build-docker run-docker tidy postgres pgadmin rm_container createdb 