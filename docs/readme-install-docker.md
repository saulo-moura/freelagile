## Pré requisitos ##

- Acesso livre ao PROXY.
- Git a versão mais recente [GIT](https://git-scm.com/book/pt-br/v1/Primeiros-passos-Instalando-Git).
- Permissão de leitura para todos os projetos do grupo Arquitetura no Git:
    - [Grupo Arquitetura](http://git.prodeb.ba.gov.br/groups/starter-pack).

## Requisitos da solução já instalados no Container Docker ##
- NodeJS
- PHP
- Extensões do PHP: xdebug, fileinfo, mbstring, pdo_pgsql, pgsql, openssl.
- Composer
- PostgreSQL

## Instalação ##

### 1) Instalando e configurando o docker ###

#### No Ubuntu ####

> Caso o passo 1 já tenha sido realizado em outro momento pulo para o passo 2.

- Instale o docker [Docker Install](https://www.docker.com/products/overview).
- Instale o docker-compose [Docker Compose](https://docs.docker.com/compose/install/).
- No linux execute os comandos abaixo para criar o grupo do docker e adicionar o usuário.

```sh
sudo groupadd docker 
```

- em seguinda adicione o usuário ao grupo criado.

```sh
sudo usermod -aG docker $USER
```

- Realize o **logoff** para que as configurações do docker sejam aplicadas.

#### No windows ####

- Baixe o executável [neste site](https://www.docker.com/) e siga as instruções do mesmo.

#### 2) Configurando o projeto ####

- Rode os comandos abaixo no terminal bash ou git bash:

```sh
cd {pasta_do_projeto}
git clone git@git.prodeb.ba.gov.br:starter-pack/php-docker.git
```
- Acesse o arquivo: **/php-docker/docker-compose.yml** e renomeie o container_name do **DB** e **WEB**
adicionando como sufixo o nome do projeto.
- O nome do host do postgres deve ser o nome do container postgres.
- exemplo:

```html
db:
  container_name: base-postgres-{nome_projeto}
web:
  container_name: base-php-fpm-{nome_projeto}
```

- Construa e inicialize os containers seguindo os passos abaixo.

```sh
cd {php-docker}
docker-compose build
docker-compose up -d
```

**Siga os próximos passos no [README](../readme.md) original**
 
> Comandos úteis:

- Abrir o Visual Studio Code (acesso o README do php-docker)

- Acessar o container

```sh
docker exec -it base-php-fpm-{nome_projeto} bash
```

- Rodar qualquer comando mo container

```sh
docker exec -it base-php-fpm-{nome_projeto} comando
```

- Listar containers

```sh
docker ps
```

**para mais informações e documentação acesse [Docker](https://www.docker.com/)**