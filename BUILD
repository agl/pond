Ubuntu 13.10

  sudo apt-get install golang git libgtk-3-dev libgtkspell3-3-dev libtspi-dev \
    trousers tor mercurial cd

  mkdir gopkg
  export GOPATH=$HOME/gopkg
  go get github.com/agl/pond/client
  go install github.com/agl/pond/client
  $GOPATH/bin/client

Debian Wheezy

Same as Ubuntu, above, but 1) on the go get command line add -tags ubuntu
before the URL and 2) the gtkspell package is called libgtkspell-3-dev. On more
recent versions of Debian, the instructions should be exactly the same as
Ubuntu.

Fedora 19

Fedora's golang package appears to be completely broken, so this installs Go
from source.

  sudo yum install gtk3-devel gtkspell3-devel gcc trousers-devel git mercurial \
    tor sudo systemctl start tor
  cd
  hg clone https://code.google.com/p/go
  cd go/src
  ./all.bash
  cd
  export PATH=$PATH:$HOME/go/bin
  mkdir gopkg
  export GOPATH=$HOME/gopkg
  go get github.com/agl/pond/client
  go install github.com/agl/pond/client

Arch

I don't have tested instructions for Arch, but one thing that will go wrong is
that Arch's Trousers build enables a GTK-2 based UI. Pond uses GTK-3 and one
cannot link GTK 2 and 3 into the same binary. You'll need the trousers package
from AUR and you'll need to edit the PKGBUILD so that the configure command has
--with-gui=openssl, not --with-gui=gtk. Then makepkg and pacman -U as normal.
In order to actually use the TPM, you'll need to systemctl start tcsd.

OS X

It's possible to get Pond building on OS X after spending lots of time with
homebrew. Something that's known to have worked,

  # you'll need an X server running in order to launch Pond unless you
  brew edit gtk+3
  # then add --enable-quartz-backend to the configure arguments
  brew install go gtk+3 gtkspell3

  export GOPATH=$HOME/gopkg
  export PATH=$PATH:$GOPATH/bin
  export PKG_CONFIG_PATH=/opt/X11/lib/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

  go get github.com/agl/pond/client
  go install github.com/agl/pond/client
  # now `client` should be in your path

TAILS only supports the cli mode of operation for Pond.
Build, install and usage instructions for TAILS users:

  sudo apt-get update --fix-missing
  sudo apt-get install -t unstable golang
  sudo apt-get install mercurial trousers gcc
  sudo apt-get install -t backports libtspi-dev
  mkdir ~/amnesia/Persistent/go/
  export GOPATH=$HOME/Persistent/go/
  export PATH=$PATH:$GOPATH/bin
  go get -d github.com/agl/pond/client
  go build -tags nogui github.com/agl/pond/client
  go install -tags nogui github.com/agl/pond/client
  export POND=experimental
  export PONDCLI=1
  alias pond-client="$GOPATH/bin/client --state-file=/home/amnesia/Persistent/.pond"

