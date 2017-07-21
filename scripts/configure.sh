#!/bin/bash

echo

EXISTING_PROJECT=false

while getopts g:e option
do
        case "${option}"
        in
                g) GIT_URL=${OPTARG};;
                e) EXISTING_PROJECT=true;;
        esac
done

if [ $EXISTING_PROJECT = false ]
then
  if [ -z $GIT_URL ]; then
      echo "É obrigatório fornecer a url do repositório git através da opção -u. Ex: sh scripts/configure.sh -g git@git.prodeb.ba.gov.br:nome-do-repositorio.git"
      exit
  fi

  # Configurando o GIT
  rm -rf .git
  git init
  git remote add origin $GIT_URL

  # Preparand oos arquivos templates
  cp public/client/paths.json.example-laravel public/client/paths.json
  cp public/client/app/app.global.js.example-laravel public/client/app/app.global.js
  rm -rf public/client/app/app.global.js.example.* public/client/paths.json.example.*

  sed -i '/paths.json/d' public/client/.gitignore
  sed -i '/app\/app.global.js/d' public/client/.gitignore
  echo "0.0.1" > VERSION
fi

# adicionando a referência do projeto do starter pack
git remote add starter-pack git@git.prodeb.ba.gov.br:starter-pack/laravel_angular_base.git

# Configurando o Projeto

composer global require "laravel/installer"
composer global require phpunit/phpunit

# Instalando as dependencias locais yoman gulp, eslint, bower e derivados
npm install -g yo gulp gulp-babel babel-preset-es2015 eslint eslint-plugin-angular bower protractor protractor-console

# Atualizando o webdriver para rodar os testes e2e
webdriver-manager update

# Instalando o gerador
npm install -g git+ssh://git@git.prodeb.ba.gov.br:starter-pack/generator-ngprodeb.git

# Dando permissão nas pastas do laravel
chmod 777 -R storage
chmod 777 -R bootstrap/cache

# Instalando as dependencias
COMPOSER_PROCESS_TIMEOUT=2000 composer install

# Gerando as chaves
php artisan key:generate
php artisan jwt:secret

# Gerando os dados de usuários padrão no banco
php artisan migrate --seed

# Dando permissão executar os scripts bash
chmod +x scripts/deploy.sh
chmod +x scripts/e2e-test.sh
chmod +x scripts/unit-test.sh

# Instalando as dependencias do frontend
cd public/client
npm install
bower install

# Voltando para pasta raiz
cd ../..

if [ $EXISTING_PROJECT = false ]
then
  # Adicionando ao stage area. Não commita automaticamente pois pode estar dentro do docker
  git add .
fi



