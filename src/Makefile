all: build-docker upload-docker

build-docker:
	docker build -t docker.netwatch.team/netwatch_telnet-attackpod:0.1 .

upload-docker:
	docker push docker.netwatch.team/netwatch_telnet-attackpod:0.1
