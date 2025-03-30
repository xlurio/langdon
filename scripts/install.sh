# /bin/bash
set -ex

cd "$HOME"

# APT Repositories (Firefox)
install -d -m 0755 /etc/apt/keyrings
wget -q https://packages.mozilla.org/apt/repo-signing-key.gpg -O- | \
    tee /etc/apt/keyrings/packages.mozilla.org.asc > /dev/null
gpg -n -q --import --import-options import-show \
    /etc/apt/keyrings/packages.mozilla.org.asc | \
    awk '/pub/{getline; gsub(/^ +| +$/,""); if($0 == "35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3") print "\nThe key fingerprint matches ("$0").\n"; else print "\nVerification failed: the fingerprint ("$0") does not match the expected one.\n"}'
echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" | tee -a /etc/apt/sources.list.d/mozilla.list > /dev/null
echo '
Package: *
Pin: origin packages.mozilla.org
Pin-Priority: 1000
' | tee /etc/apt/preferences.d/mozilla

# APT Packages
apt update -y ; apt install -y tor firefox build-essential libssl-dev \
    zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl git libncursesw5-dev \
    xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev dnsutils nmap \
    ffmpeg

# PyEnv
curl -fsSL https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init - bash)"' >> ~/.bashrc
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.profile
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.profile
echo 'eval "$(pyenv init - bash)"' >> ~/.profile
exec "$SHELL"

# Python
pyenv install 3
pyenv global 3
exec "$SHELL"

# Python packages
pip install --upgrade pip
python -m pip install --user dnsgen wafw00f

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
exec "$SHELL"

# Rust packages
cargo install apkeep

# Go
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.bashrc
exec "$SHELL"

# Go Packages
go install \
    github.com/tomnomnom/assetfinder@latest \
    github.com/lc/gau/v2/cmd/gau@latest \
    github.com/OJ/gobuster/v3@latest \
    github.com/sensepost/gowitness@latest \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# ExploitDB
git clone https://gitlab.com/exploit-database/exploitdb.git
echo 'export PATH="$PATH:$HOME/exploitdb"' >> ~/.bashrc
exec "$SHELL"

# MassDNS
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
cd bin
chmod +x massdns
echo 'export PATH="$PATH:$HOME/massdns/bin"' >> ~/.bashrc
cd "$HOME"
exec "$SHELL"

# Webanalyze
mkdir webanalyze
cd webanalyze
wget https://github.com/rverton/webanalyze/releases/download/v0.4.1/webanalyze_Linux_x86_64.tar.gz
tar -xvf webanalyze_Linux_x86_64.tar.gz
chmod +x webanalyze
echo 'export PATH="$PATH:$HOME/webanalyze"' >> ~/.bashrc
cd "$HOME"
exec "$SHELL"

# WhatWeb
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
chmod +x whatweb
echo 'export PATH="$PATH:$HOME/WhatWeb"' >> ~/.bashrc
cd "$HOME"
exec "$SHELL"

# Wordlists
git clone https://github.com/danielmiessler/SecLists.git
mkdir jhaddix
cd jhaddix
wget https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
cd $HOME

# Langdon
git clone https://github.com/xlurio/langdon.git
pip install --user poetry
poetry install -C "$HOME/langdon"
rm "$HOME/.local/bin/httpx" # Causes conflict with the go version

echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
exec $SHELL

# Create recoinassaince directory
mkdir -p "$HOME/recon"
langdon init --resolvers_file "$HOME/massdns/lists/resolvers.txt" \
    --dns_wordlist "$HOME/jhaddix/all.txt"
    --content_wordlist "$HOME/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt"
    --directory "$HOME/recon"
touch "$HOME/recon/start.sh"
echo '#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <scope_csv_file>"
    exit 1
fi

langdon importcsv "$1"

supervisord -c /etc/supervisord.conf
' >> "$HOME/recon/start.sh"
chmod 754 "$HOME/recon/start.sh"

# Supervisor
pip install --user supervisor
exec "$SHELL"
echo_supervisord_conf > /etc/supervisord.conf
echo '
[program:langdon]
command=python -m langdon run
directory='$HOME'/recon
' >> /etc/supervisord.conf
