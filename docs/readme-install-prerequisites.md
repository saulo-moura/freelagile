## Instalando os pré requisitos ##

> Obs.: Caso os pré requisitos já estejam instalados passe para o passo de Configuração

- Em uma instalação limpa do Linux Mint ou Ubuntu os comandos a seguir instalam os pré requisitos:

```sh
curl -sL https://deb.nodesource.com/setup_6.x | sudo bash -

sudo apt-get update && sudo apt-get install -y build-essential libxml2-dev libfreetype6-dev libjpeg-turbo8-dev libmcrypt-dev libpng12-dev libssl-dev libpq-dev git vim unzip postgresql-9.5 postgresql-client nodejs php7.0 php7.0-pgsql php7.0-xml php7.0-zip php7.0-cli php7.0-common php7.0-gd php7.0-mbstring php7.0-mcrypt php7.0-readline php7.0-json pgadmin3

sudo curl -sS https://getcomposer.org/installer | sudo php -- --install-dir=/usr/local/bin --filename=composer

mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
```

- adicione a linha a seguir no final do arquivo **~/.bashrc**.

```sh
export PATH=~/.npm-global/bin:$PATH
```

- rode os comandos abaixo para completar a instalação:

```sh
source ~/.bashrc

sudo -u postgres psql
alter user postgres password 'root';
\q

sudo chown $(whoami):$(whoami) -R ~/.composer

```

- Aplicaque o fix abaixo para alterar limite de watches do gulp

```sh
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
```