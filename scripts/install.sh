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
    xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev dnsutils nmap

# PyEnv
curl -fsSL https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init - bash)"' >> ~/.bashrc
exec "$SHELL"

# Python
pyenv install 3
pyenv global 3

# Python packages
python -m pip install --user dnsgen wafw00f

# Ruff
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
exec "$SHELL"

# Ruff packages
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

# Langdon
git clone https://github.com/xlurio/langdon.git
cd langdon
pipx install poetry
poetry install
cd "$HOME"
