#!/bin/bash

# Script de deploy - Starter Pack

## Variables Block
EXTENSION='.zip'
DEPLOY_DIR='deploy'
ERROR=false
TYPE_FTP="null"
CR=`echo '\n.'`
CR=${CR%.}

## Color Block
RED='\033[0;31m'
GREEN='\033[0;32m'
BCYAN='\033[1;36m'
NO_COLOR='\033[0m'

## Funcões que printam as mensagens no console
write() { echo "${NO_COLOR}$1${NO_COLOR}"; }
error() { echo "${RED}Error: ${1}${NO_COLOR}"; }
success() { echo "${BCYAN}$1${NO_COLOR}"; }
## Funcões que printam as mensagens no console

## Função para criação de arquivo
createFile() {
  if [ ! -f "$1" ]
  then
    touch $1
  fi
}

## Função para criação de diretório
createDir() {
  if [ ! -d "$1" ]
  then
      mkdir -p $1
  fi
}

## Função para remoção de arquivos ou diretórios
removeFileOrDir() {
  for ORIGIN in $@ ; do
    if [ -d "$ORIGIN" ] || [ -f "$ORIGIN" ] ;
    then
        rm -rf $ORIGIN
    fi
  done
}

## Função que copia arquivos para o $DEPLOY_DIR
copy() {
  for ORIGIN in $@
  do
    cp -r $ORIGIN $DEPLOY_DIR
  done
}

## Função que copia o arquivo .env para o $DEPLOY_DIR
copyEnv() {
  if [ ! -f $1 ]
  then
      error "O arquivo $1 não foi encontrado."
      exit
  else
      copy $1
      mv "deploy/$1" "deploy/.env"
  fi
}

## Função que escreve no arquivo .htaccess
writeInHtaccess() {
URL=$1
URL_NOPRO=${URL#*//}
echo "<IfModule mod_rewrite.c>
  Header set Access-Control-Allow-Origin \"*\"
	Header set Access-Control-Allow-Headers \"Origin, Content-Type, Accept, Authorization, X-Requested-With\"
	Header set Access-Control-Allow-Methods \"POST, GET, OPTIONS, PUT, DELETE\"
  RewriteEngine On
  RewriteCond %{HTTP_HOST} ^$URL_NOPRO$
  RewriteRule (.*) /public/\$1 [L]
</IfModule>" >> .htaccess
}

## Função que executa os comandos do artisan
executePHPArtisan() {
  for ORIGIN in $@
  do
    php artisan $ORIGIN
  done
}

## Função que interrope o script com erro
exitError() {
  error "$1"
  removeFileOrDir $DEPLOY_DIR $PACKAGE_NAME
  exit
}

## Função que verifica se o arquivo existe
verifyIfFileExists() {
  for ORIGIN in $@ ; do
    if [ ! -f "$ORIGIN" ] ;
    then
        exitError "O arquivo (${ORIGIN}) não foi encontrado, não é possível prosseguir sem ele."
    fi
  done
}

## Função que verifica se o diretório existe
verifyIfDirExists() {
  for ORIGIN in $@ ; do
    if [ ! -d "$ORIGIN" ] ;
    then
        exitError "O diretório (${ORIGIN}) não foi encontrado, não é possível prosseguir sem ele."
    fi
  done
}

## Função que carrega os dados do arquivo .env
loadingEnvFile() {
  . ./.env
}

## Função que verifica se os parâmetros do FTP foram setados
varifyParamsFTP() {
  write '\nAcessando dados de FTP no arquivo .env...'

  if [ -z ${FTP_HOST+x} ] ;
  then
    exitError "\nFTP_HOST no arquivo .env.production não foi definido.\n"
  fi

  if [ -z ${FTP_USER+x} ] ;
  then
    exitError "\nFTP_USER no arquivo .env.production não foi definido.\n"
  fi

  if [ -z ${FTP_PASSWD+x} ] ;
  then
    exitError "\nFTP_PASSWD no arquivo .env.production não foi definido.\n"
  fi

  if [ -z ${FTP_DIR+x} ] ;
  then
    exitError "\nFTP_DIR no arquivo .env.production não foi definido.\n"
  fi

}

## Função que adiciona arquivos ao pacote zipado
addInFileZip() {
  for ORIGIN in $@
  do
    zip -u -r -q $PACKAGE_NAME $ORIGIN
  done
}

## Função que acessa o ftp
openFtp() {
  echo "open $FTP_HOST
  user $FTP_USER $FTP_PASSWD
  cd $FTP_DIR
  binary" > /tmp/ftp.$$
}
## Função que executa comantos no ftp
executeInFtp() {
  echo $1 >> /tmp/ftp.$$
}

## Função que fecha o ftp
closeFtp() {
  echo "quit" >> /tmp/ftp.$$
}

## Função que executa os comando do arquivo /tmp/ftp
runFtp() {
  echo "LOG:" > /tmp/log.$$
  ftp -inv < /tmp/ftp.$$ >> /tmp/log.$$
  rm -f /tmp/ftp.$$
}

success ':::: Iniciando Procedimento ::::'

SEND_TO_FTP=true

while true ; do
  read -p "Deseja, ao final, enviar o pacote gerado para o FTP (s/n)? " sn
  case $sn in
    [Ss]* ) SEND_TO_FTP=true; break;;
    [Nn]* ) SEND_TO_FTP=false; break;;
    *) error "Opção inválida. Digite (S) para sim ou (N) para não.";;
  esac
done

if [ "$SEND_TO_FTP" = true ]
then
  while true ; do
    read -p "Para qual FTP será enviado o pacote? $CR( 1 ) Desenvolvimento $CR( 2 ) Homologação $CR( 3 ) Produção $CR" n
    case $n in
      1) TYPE_FTP="d"; break;;
      2) TYPE_FTP="h"; break;;
      3) TYPE_FTP="p"; break;;
      *) error "Opção inválida.";;
    esac
  done
fi

# Permissão de manipulação da pasta
sudo chown $(whoami):$(whoami) . -R

sudo apt-get -qq -y install pv

# Cria o diretorio temporário(deploy)
createDir $DEPLOY_DIR

write '\nCopiando arquivos...'

## Copiando o arquivo .env.TYPE_FTP e renomeando para .env
copyFileEssential() {
  if [ "$SEND_TO_FTP" = true ]
  then
    if [ "$TYPE_FTP" = "h" ]
    then
      copyEnv .env.homologation
    elif [ "$TYPE_FTP" = "p" ]
    then
      copyEnv .env.production
    fi
  fi

  if [ "$SEND_TO_FTP" = false ] || [ "$TYPE_FTP" = "d" ]
  then
    copyEnv .env.development
  fi

  ## Verificando se as pastas e arquivos obrigratórios existem
  verifyIfFileExists public/client/gulpfile.js
  verifyIfDirExists app bootstrap config public resources storage vendor public/client/bower_components

  ## Copiando os diretórios e arquivos necessários para produção
  copy bootstrap storage artisan public/client/gulpfile.js

  rsync -a --exclude='client/bower_components' --exclude='client/node_modules' --exclude='client/build' --exclude='client/tests' public $DEPLOY_DIR

  if [ ! -L $PWD/$DEPLOY_DIR/vendor ]; then ln -s $PWD/vendor $PWD/$DEPLOY_DIR/vendor; fi
  if [ ! -L $PWD/$DEPLOY_DIR/resources ]; then ln -s $PWD/resources $PWD/$DEPLOY_DIR/resources; fi
  if [ ! -L $PWD/$DEPLOY_DIR/config ]; then ln -s $PWD/config $PWD/$DEPLOY_DIR/config; fi
  if [ ! -L $PWD/$DEPLOY_DIR/app ]; then ln -s $PWD/app $PWD/$DEPLOY_DIR/app; fi
  if [ ! -L $PWD/$DEPLOY_DIR/routes ]; then ln -s $PWD/routes $PWD/$DEPLOY_DIR/routes; fi
  if [ ! -L $PWD/$DEPLOY_DIR/public/client/bower_components ]; then
    ln -s $PWD/public/client/bower_components $PWD/$DEPLOY_DIR/public/client/bower_components;
  fi
  if [ ! -L $PWD/$DEPLOY_DIR/public/client/node_modules ]; then
    ln -s $PWD/public/client/node_modules $PWD/$DEPLOY_DIR/public/client/node_modules;
  fi

  mkdir -p $DEPLOY_DIR/public/client/build
}
copyFileEssential | pv -p -e -t -a -r > /dev/null

## Acessando a pasta deploy
cd $DEPLOY_DIR/

# Cria o arquivo .htaccess no $DEPLOY_DIR
createFile .htaccess

write '\nExecutando comandos do php artisan para limpeza do cache e logs...\n'

## Limpando cache e logs do laravel
clarCacheAndClearLogs() {
  executePHPArtisan cache:clear route:clear view:clear config:clear clear-compiled
}
clarCacheAndClearLogs | pv -p -e -t -a -r > /dev/null

write '\nRemovendo os arquivos de log, sessions e cache...'

## Removendo os arquivos de log, sessions e cache
removeLogAndSessionsAndCacheFiles() {
  removeFileOrDir storage/logs/* storage/framework/sessions/* storage/framework/cache/*
}
removeLogAndSessionsAndCacheFiles | pv -p -e -t -a -r > /dev/null

write '\nOtimizando o projeto...\n'

## Otimizando o projeto
executePHPArtisan optimize | pv -p -e -t -a -r > /dev/null

write '\nExecutando gulp para minificar js e css...'

## Gerando os arquivos minificados .js e .css
gulp --gulpfile public/client/gulpfile.js --production

write '\nRemovendo fontes do js e css...'

## Removendo os arquivos .js e .css
removeJsAndCssFiles() {
  removeFileOrDir public/client/app/*.js public/client/app/**/*.js public/client/app/**/**/*.js public/client/styles/*.scss
}
removeJsAndCssFiles | pv -p -e -t -a -r > /dev/null

write '\nRemovendo diretorio de exemplos...'

## Removendo o diretório de exemplos
removeDirSamples() {
  removeFileOrDir public/client/app/samples
}
removeDirSamples | pv -p -e -t -a -r > /dev/null

## Carregando dados do arquivo .env
loadingEnvFile

## Gera o $PACKAGE_NAME com a extensão .zip
PACKAGE_NAME=$PKG_NAME$EXTENSION

# Permissão de manipulação da pasta
chown $(whoami):$(whoami) . -R

## Escrevendo no arquivo .htaccess
writeInHtaccess $APP_URL

write '\nZipando...'

## Criando o pacote zipado do projeto
zipProject() {
  zip -rq $PACKAGE_NAME .env .htaccess
  addInFileZip resources/ app/ bootstrap/ config/ storage/ vendor/ routes/

  ## Atualizando o pacote zipado
  addInFileZip artisan public/index.php public/.htaccess public/robots.txt public/client/index.html
  addInFileZip public/client/app/ public/client/build/ public/client/images/ public/client/styles/
}
zipProject | pv -p -e -t -a -r > /dev/null

write '\nCopiando pacote para a pasta raiz do projeto...'

## Copiando o pacote para a pasta raiz do projeto
cp $PACKAGE_NAME ../ | pv -p -e -t -a -r > /dev/null

## Volta para a pasta raiz do projeto
cd ../

write '\nRemovendo pasta deploy(temporária)...'

## Removendo o diretório de deploy
removeFileOrDir $DEPLOY_DIR | pv -p -e -t -a -r > /dev/null

if [ "$SEND_TO_FTP" = true ] ; then

  ## Lendo os dados de FTP do arquivo .env
  varifyParamsFTP | pv -p -e -t -a -r > /dev/null

  write '\nEnviando para FTP: '$FTP_HOST

  ## Transferindo para o FTP
  sendPackageToFTP() {
  openFtp

  if [ "$TYPE_FTP" != "p" ]
  then
    executeInFtp "delete .htaccess"
    executeInFtp "put unpack.php"
  fi

  executeInFtp "put "$PACKAGE_NAME
  closeFtp
  runFtp

  if grep -Fxq "530 Login authentication failed" /tmp/log.$$
  then
    rm -f /tmp/log.$$
    exitError "Ocorreu uma falha na autenticação!"
  elif grep -Fxq "550" /tmp/log.$$
  then
    rm -f /tmp/log.$$
    exitError "Ocorreu uma falha na transferência dos arquivos: Arquivo não encontrado!"
  elif grep -Fxq "553" /tmp/log.$$
  then
    rm -f /tmp/log.$$
    exitError "Ocorreu uma falha na transferência dos arquivos: Permissão Negada!"
  fi

  rm -f /tmp/log.$$

  }
  sendPackageToFTP | pv -p -e -t -a -r > /dev/null

  removeFileOrDir $PACKAGE_NAME

  success "\n:::: $PACKAGE_NAME enviado para o FTP com sucesso! ::::"

  if [ "$TYPE_FTP" != "p" ]
  then

    write "\n Instalando...\n"

    installPackageInServer() {
    curl $APP_URL"/unpack.php?pkgName="$PACKAGE_NAME"&url="$APP_URL"&dir="$FTP_DIR | php

    ## Removendo os arquivos de deploy do FTP
    openFtp
    executeInFtp "delete $PACKAGE_NAME"
    executeInFtp "delete unpack.php"
    closeFtp
    runFtp

    rm -f /tmp/log.$$
    }
    installPackageInServer | pv -p -e -t -a -r > /dev/null

    success "\n:::: $APP_NAME instalado com sucesso! ::::"

    write "\n Abrindo navegador...\n"

    if which xdg-open > /dev/null
    then
      xdg-open $APP_URL
    elif which gnome-open > /dev/null
    then
      gnome-open $APP_URL
    fi
  fi

  write "\n Removendo "$PACKAGE_NAME"\n"
else
  success "\n:::: $PACKAGE_NAME gerado com sucesso! ::::\n"
fi

exit 0
