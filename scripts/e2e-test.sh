#!/bin/bash

# Limpando a base de test e rodando os seeds
APP_ENV=testing php artisan migrate:reset --quiet
APP_ENV=testing php artisan migrate --seed --quiet

# Iniciando o servidor no modo de test
( APP_ENV=testing php artisan serve --quiet -n --port=5020 --host=0.0.0.0 --no-ansi & ) > /dev/null 2>&1

# Rodando os testes do front-end
protractor public/client/tests/conf.js $1

# Mata o processo do servidor
lsof -t -i tcp:5020 | xargs kill -9
