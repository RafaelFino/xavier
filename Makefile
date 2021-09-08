uatu:
	go build -o bin/uatu -v cmd/uatu/main.go

thanos:
	go build -o bin/thanos -v cmd/thanos/main.go

all: 
	scripts/build.sh