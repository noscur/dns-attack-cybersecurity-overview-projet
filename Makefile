all: install setup

install:
	@echo "Check if docker is installed."
	@command -v docker >/dev/null 2>&1 || { echo >&2 "Docker is not installed, check https://docs.docker.com/engine/install/ to install it."; exit 1; }
	@echo "Docker is installed !"

setup:
	@echo "Creation of a docker virtual network"
	@docker network create --subnet=172.23.0.0/16 cyberproject-network

clean:
	@echo "Removing docker virtual network"
	@docker network rm cyberproject-network