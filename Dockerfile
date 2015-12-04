# Run pond-client or pond-server via a Docker container
#
# USAGE:
#	# build the image
# 	docker build -t pond .
#
#	# start a torproxy container
# 	docker run -d -p 9050:9050 --name torproxy jess/tor-proxy
#
# 	# run pond-client
# 	docker run -it --net container:torproxy pond
#
# 	# run pond-server
# 	docker run -it --net container:torproxy \
# 		-v /you/host/dir:/home/pond/pond-server-base \
# 		pond pond-server --init --base-directory /home/pond/pond-server-base
#
FROM debian:jessie
MAINTAINER Jessica Frazelle <jess@docker.com>

ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go

RUN	apt-get update && apt-get install -y \
	ca-certificates \
	libgtk-3-0 \
    libgtkspell3-3-0 \
	libtspi1 \
	--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/*

COPY . /go/src/github.com/agl/pond

# Make the most minimal image
RUN buildDeps=' \
		golang \
		git \
		gcc \
		libgtk-3-dev \
		libgtkspell3-3-dev \
		libtspi-dev \
		pkg-config \
	' \
	set -x \
	&& apt-get update \
	&& apt-get install -y $buildDeps --no-install-recommends \
	&& cd /go/src/github.com/agl/pond \
	&& go get -d -v github.com/agl/pond/client \
	&& go get -d -v github.com/agl/pond/server \
	&& go build -o /usr/bin/pond-client ./client \
	&& go build -o /usr/bin/pond-server ./server \
	&& apt-get purge -y --auto-remove $buildDeps \
	&& rm -rf /var/lib/apt/lists/* \
	&& rm -rf /go \
	&& echo "Build complete."

# create pond user
ENV HOME /home/pond
RUN useradd --create-home --home-dir $HOME pond \
	&& chown -R pond:pond $HOME

WORKDIR $HOME
USER pond

CMD [ "pond-client", "-cli" ]
