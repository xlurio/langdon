# /bin/bash
set -ex

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <recon_project_directory>"
    exit 1
fi

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
apt update -y ; apt install -y build-essential libssl-dev \
    zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl git libncursesw5-dev \
    xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev dnsutils nmap \
    ffmpeg graphviz ruby-full libyaml-dev tor firefox

# PyEnv
curl -fsSL https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc

echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.profile
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.profile

. ~/.bashrc

echo 'eval "$(pyenv init - bash)"' >> ~/.bashrc
echo 'eval "$(pyenv init - bash)"' >> ~/.profile

. ~/.bashrc

# Python
pyenv install 3
pyenv global 3
. ~/.bashrc

# Python packages
pip install --upgrade pip
python -m pip install --user dnsgen wafw00f

# Ruby Bundler
gem install bundler

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
. ~/.bashrc

# Rust packages
cargo install apkeep

# Go
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.bashrc
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.profile
. ~/.bashrc

# Go Packages
go install github.com/003random/getJS/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
echo 'export PATH="$PATH:'$HOME'/go/bin"' >> ~/.bashrc
echo 'export PATH="$PATH:'$HOME'/go/bin"' >> ~/.profile
. ~/.bashrc

# ExploitDB
git clone https://gitlab.com/exploit-database/exploitdb.git
cd exploitdb
chmod +x searchsploit
echo 'export PATH="$PATH:$HOME/exploitdb"' >> ~/.bashrc
echo 'export PATH="$PATH:$HOME/exploitdb"' >> ~/.profile
cd "$HOME"
. ~/.bashrc

# MassDNS
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
cd bin
chmod +x massdns
echo 'export PATH="$PATH:$HOME/massdns/bin"' >> ~/.bashrc
echo 'export PATH="$PATH:$HOME/massdns/bin"' >> ~/.profile
cd "$HOME"
. ~/.bashrc

# Webanalyze
mkdir webanalyze
cd webanalyze
wget https://github.com/rverton/webanalyze/releases/download/v0.4.1/webanalyze_Linux_x86_64.tar.gz
tar -xvf webanalyze_Linux_x86_64.tar.gz
chmod +x webanalyze
echo 'export PATH="$PATH:$HOME/webanalyze"' >> ~/.bashrc
echo 'export PATH="$PATH:$HOME/webanalyze"' >> ~/.profile
cd "$HOME"
. ~/.bashrc

# WhatWeb
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
bundle update
bundle install
chmod +x whatweb
echo 'export PATH="$PATH:$HOME/WhatWeb"' >> ~/.bashrc
echo 'export PATH="$PATH:$HOME/WhatWeb"' >> ~/.profile
cd "$HOME"
. ~/.bashrc

# Wordlists
git clone https://github.com/danielmiessler/SecLists.git

# Langdon
git clone https://github.com/xlurio/langdon.git
pip install --user poetry
poetry config virtualenvs.create false
poetry install -C "$HOME/langdon"

echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
. ~/.bashrc

# Create recoinassaince directory
mkdir -p "$1"
poetry run -P "$HOME/langdon" \
    langdon -- init --resolvers_file "$HOME/massdns/lists/resolvers.txt" \
    --dns_wordlist "$HOME/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" \
    --content_wordlist "$HOME/SecLists/Discovery/Web-Content/common.txt" \
    --directory "$1"
echo '#!/bin/bash

set -xe

if [ -z "$1" ]; then
    echo "Usage: $0 <scope_csv_file>"
    exit 1
fi

poetry run -P "'$HOME'/langdon" langdon -- importcsv "$1"

supervisord -c /etc/supervisord.conf
' > "$1/start.sh"
chmod 754 "$1/start.sh"

# Supervisor
pip install --user supervisor
. ~/.bashrc
echo_supervisord_conf > /etc/supervisord.conf
echo '
[program:langdon-run]
command=poetry run --project="'$HOME'/langdon" --directory="'$1'" langdon -- --loglevel DEBUG run

[program:langdon-graph]
command=poetry run --project="'$HOME'/langdon" --directory="'$1'" langdon -- --loglevel DEBUG graph
autorestart=true
' >> /etc/supervisord.conf

# Generate subfinder config
subfinder -ls
