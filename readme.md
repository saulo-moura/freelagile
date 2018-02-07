
# Sistema Starter Pack PHP #

## Status

[![build status](https://gitlab.com/thiagoaos/starter-pack-php/badges/master/build.svg)](https://gitlab.com/thiagoaos/starter-pack-php/commits/develop)
[![coverage report](https://gitlab.com/thiagoaos/starter-pack-php/badges/master/coverage.svg)](https://gitlab.com/thiagoaos/starter-pack-php/commits/develop)

## Sobre ##

- Este projeto tem como objetivo servir de base para futuros projetos da PRODEB.
- Como framework backend o sistema utiliza o Laravel 5.4.
- Como framework frontend o sistema utiliza o AngularJS 1.5.
- Para autenticação o sistema utiliza [JWT](http://jwt.io) através da lib [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth)
- O sistema não faz uso de sessão para identificação do usuário, toda a informação é através do token enviado/recebido
- Todas as funcionalidades retornam um json contendo as informações requisitadas.

## Pré requisitos ##

- Acesso livre ao PROXY.
- Preferencialmente utilize o Linux com o gerenciador APT.
  - Caso o SO seja windows deve utilizar a instalação do projeto via [Docker](docs/readme-install-docker.md).
- Um editor decente.
    - Recomendado: [Visual Studio Code](https://code.visualstudio.com/) ou [ATOM](https://atom.io/).
- Git a versão mais recente [GIT](https://git-scm.com/book/pt-br/v1/Primeiros-passos-Instalando-Git).
- Permissão de leitura para todos os projetos do grupo Arquitetura no Git:
    - [Grupo Arquitetura](http://git.prodeb.ba.gov.br/groups/starter-pack).
- NodeJS versão 6.x.x ([tutorial para instalar](https://nodejs.org/en/download/package-manager/)).
    - Configure o npm para rodar sem sudo ([tutorial](https://docs.npmjs.com/getting-started/fixing-npm-permissions)).
    - Verifique a versão do npm **npm --version** (deve ser igual ou superior a 3.5.1).
- PHP com a versão 7.0.x ([tutorial para instalar](http://tecadmin.net/install-php5-on-ubuntu/)).
- Extensões do PHP: xdebug, fileinfo, mbstring, mycript, tokenizer, xml, pdo, pdo_pgsql, pgsql, openssl, ldap, zip.
- Composer ([tutorial para instalar](https://getcomposer.org/doc/00-intro.md#globally)).
- PostgreSQL ([tutorial para instalar] (https://www.vivaolinux.com.br/dica/Instalando-o-PostgreSQL-e-pgAdmin3-no-Ubuntu)).

## Componentes e Frameworks ##

> Componentes e frameworks utilizados no frontend do projeto:

- [AngularJS](https://angularjs.org)
- [Angular Material](https://material.angularjs.org)
- [NgProdeb](https://git.prodeb.ba.gov.br:starter-pack/ngprodeb)
- [MomentJS](http://momentjs.com/)

## Funcionalidades ##

> Funcionalidades atualmente disponíveis no projeto

- Containers Docker com os pré requisitos instalados [PHP Docker](http://git.prodeb.ba.gov.br/starter-pack/php-docker);
- Autenticação via token com o JWT (Dispensando o uso de sessão);
- Gerador automático de estrutura de arquivo (Servidor);
- Encapsulamento do CRUD no servidor com a classe **CrudController**;
- Formatação dos atributos do Model no servidor;
- LOG (Gerenciador de logs do sistema);
- Auditoria;
- Gerador de pacote para produção;
- Envio do pacote via FTP;
- Implementação do [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS);
- Gerenciamento de usuário;
- Consultas dinâmicas;
- Envio de emails para usuário;
- Integração com o [Angular Client](http://git.prodeb.ba.gov.br/starter-pack/starter-pack-angular-client.git);
- Integração com o [Generator NgProdeb](http://git.prodeb.ba.gov.br/starter-pack/generator-ngprodeb.git);

## Clone o Projeto ##

```sh
git clone git@git.prodeb.ba.gov.br:starter-pack/laravel_angular_base.git {nome_projeto} 
```

> Escolha uma das 2 opções de instalação

## Instalação via DOCKER ## 

- Seguir a instalação do DOCKER e dos Containers Docker via [README Instalação Docker](docs/readme-install-docker.md).
- Depois pule para o item desse guia chamado **Configurando o projeto**
- Para o Docker, todos os comandos descritos neste guia, devem ser executados de dentro do bash do container
- Para entrar no bash do container execute no terminal


```sh
cd {pasta_do_projeto}
docker exec -it base-php-fpm-{nome_projeto} bash
```

## Instalação Tradicional ##

- Seguir a instalação dos pré requisitos via [README Instalação Pré Requisitos](docs/readme-install-prerequisites.md).

## Configurando o projeto ##


```sh
cd {pasta_do_projeto}
cp .env.development .env
```
- Ajuste o **.env** com as informações do banco de dados, email e etc...
- No Docker, o host do postgres é o container_name do db que fica no docker-compose.yml

### Se o projeto foi clonado do repositório do Starter Pack e ninguém configurou ###

```sh
# lembre de ajustar o .env
cd {pasta_do_projeto}
sh scripts/configure.sh -g git@git.prodeb.ba.gov.br:repositorio-do-seu-projeto.git
```

### Se o projeto já foi configurado e clonado do repositório do projeto ###

```sh
# lembre de ajustar o .env
cd {pasta_do_projeto}
sh scripts/configure.sh -e
```

## Colocando para Rodar ##

- Execute o comando abaixo para processar os arquivos **.sass** e concatenar os **.js** e **.css** injetando no **index.html**.
- O comando fica observando futuras modificações e repetindo o processo automaticamente

```sh
cd {pasta_do_projeto}
npm run build
```

- Em outra aba do terminal rode o comando abaixo para levantar o servidor php:

```sh
cd {pasta_do_projeto}
npm run server (Este comando inicia o servidor php na porta 5000)
```

- Abra a url **http://localhost:5000** no navegador e logue com os dados:

  - email: **admin-base@prodeb.com** 
  - senha: **Prodeb01**

## Verificação do código ##

```sh
cd {pasta_do_projeto}
npm run check
```

- Verifica a formatação do código javascript
  - parametros opcionais
    - **--fix** (para corrigir os erros que podem ser corrigidos automaticamente)

## Testes Automatizados ##

### Cobertura Atual ###

![Cobertura](coverage.png)

### Configuração ###

- Crie uma database para ser utilizada nos testes.
- Ajuste o .env.testing com as informações do banco de dados criado;
- Nos testes são utilizados as informações do seeds. 

### Colocando para Rodar ###

#### Testes e2e (end to end) ####

- Em um terminal execute os comandos abaixo:

```sh
cd {pasta_do_projeto}
npm run webdriver
```

  - Em outro terminal execute os comandos abaixo:

```sh
cd {pasta_do_projeto}
npm run e2e-test
```

#### Testes unitários ####

- Em um terminal execute os comandos abaixo:

```sh
cd {pasta_do_projeto}
npm run unit-test
```

## Atualizando o projeto com base nos repositórios oficiais do Starter Pack ##

- A forma do merge abaixo deixa os arquivos modificados na área de stage, onde é possível optar por commitar ou descartar as modificações.

### Merge com Starter Pack ###

```sh
cd {pasta_do_projeto}
git fetch starter-pack 
git merge starter-pack/develop --squash --no-commit
# com esse comando o merge fica em andamento, esperando confirmação através de um commit
```

## Log ##

> Para ver os logs

- Acesse [http://localhost:5000/developer/log-viewer](http://localhost:5000/developer/log-viewer)
- Digite o usuário conforme a variável de ambiente no arquivo .env DEVELOP_ID
- Digite a senha conforme a variável de ambiente no arquivo .env DEVELOP_PASSWORD

## Informações do Ambiente ##

> Para ver as informações do Ambiente

- Acesse [http://localhost:5000/decompose](http://localhost:5000/decompose)
- Digite o usuário conforme a variável de ambiente no arquivo .env DEVELOP_ID
- Digite a senha conforme a variável de ambiente no arquivo .env DEVELOP_PASSWORD

## Gerar Pacote para Produção/Homologação ##

- Altere os dados do arquivo **.env.nome-do-ambiente** com as configurações de produção (pkg_name, banco, smtp, nível de log, ftp e etc) e desative o debug.
- Rode o comando

```sh
# lembre de ajustar o arquivo .env.nome-do-ambiente
cd {pasta_do_projeto}
npm run package
```

- Este comando 
  - prepara a aplicação para o ambiente informado, minificando os arquivos js, css e modificando o index.html para apontar para os arquivos minificados
  - gerando o pacote zipado no padrão **{NomeProjeto}.zip**.
  - Perguntar se deseja enviar para o ftp
    - caso queira:
      - O pacote será enviado
      - Descompactado
      - O pacote será removido do FTP e da raiz do projeto no filesystem local
      - O navegador padrão vai ser aberto no endereço informado no APP_URL no arquivo .env
    - caso contrário 
      - o pacote gerado com o nome **{NomeProjeto}.zip** constará na raiz do projeto

## Scripts e comandos ##

- Todos os scripts e comandos devem ser rodados dentro da pasta raiz do projeto

### Scripts ###

- sh scripts/configure.sh

### Comandos ###

- npm run server
- npm run package
- npm run build
- npm run check
- npm run webdriver
- npm run e2e-test
- npm run unit-test

## Contribuição com o Starter Pack ##

- Acesse a documentação específica [README Para Contribuição](/docs/readme-contribute.md)

## Desenvolvimento ##

> ### Editor ###

- [vscode](https://code.visualstudio.com/)
  - plugins utilizados:
      - php debug
      - php code format
      - eslint (para verificar erros de formatação e code smell no javascript)
      - editor config (para configurar codificação, tabulação ...)
      - beautify (para formatar o código)
      - path intellisense (autocomplete para php)
      - angular material snippets
      - auto close tag
      - html css class completion

> ### Geradores automáticos de arquivos ###

- Use os geradores de estrutura de arquivo para gerar os arquivos necessários para o recurso.

>  Para gerar estrutura de arquivos do lado cliente, use o comando abaixo:

```sh
cd {pasta_do_projeto}
yo ngprodeb
```

- Escolha a estrutura na lista
- Digite o nome do recurso

**Para mais detalhes sobre o uso do gerador acesse [Generator NgProdeb](http://git.prodeb.ba.gov.br/generator-ngprodeb/tree/master)**

> Para gerar estrutura de arquivos do lado servidor, use os comandos abaixo:

- Estrutura completa

```sh
php artisan crud:generate {Recurso} --fields="{field_1}#string; {field_2}#text;" --controller-namespace={Recurso} --route-group={groupName}
```

- Controller

```sh
php artisan crud:controller {Recurso}Controller --crud-name={recurso} --model-name={Recurso} --route-group={recurso}
```

- Model

```sh
php artisan crud:model {Recurso} --fillable="['{field_1}', '{field_2}']"
```

- Migration

```sh
php artisan crud:migration {recurso} --schema="{field_1}#string; {field_2}#text"
```

> Obs.: Após a criação da Estrutura completa ou de uma Migration acesse o arquivo de migration
> dentro da pasta database > migrations e Remova a linha **$table->timestamps()** e adicione as linhas abaixo:

```php
$table->timestampTz('created_at');
$table->timestampTz('updated_at');
```

> Após o processo, rode o comando abaixo para aplicar as migrations criadas

```sh
php artisan migrate
```

> Se necessário, inclua uma nova rota no arquivo **/app/Http/routes.php**

**Para mais detalhes sobre o uso do gerador acesse [CRUD Generator](https://github.com/appzcoder/crud-generator#commands)**
  
> ### Convenções ###
> (convenções adotadas para padronização do projeto)

  - Deve ser usado o gerador de estrutura de arquivos para gerar os arquivos no padrão que o sistema comporta

> ### CRUD ###

**CrudController.php** (app/Http/controllers/CrudController.php)

- Para herdar as funcionalidades, basta, no controller executar:

```php
use App\Http\Controllers\CrudController;

class {NOME_DO_CONTROLLER} extends CrudController
```

- Deve ser implementado os métodos

```php
getModel() //retornar a classe referente ao model
getValidationRules(Request $request, Model $obj) //retornar um array com as regras de validação
```

- Ações Implementadas

```php
index(Request $request)
store(Request $request)
show(Request $request, $id)
update(Request $request, $id)
saveOrUpdate(Request $request, $obj, $action)
destroy(Request $request, $id)
```

- Gatilhos

```php
applyFilters(page, $request, $baseQuery)
beforeAll($request)
beforeSearch($request, $dataQuery, $countQuery)
beforeSave($request, $obj)
beforeStore($request, $obj)
beforeUpdate($request, $obj)
beforeDestroy($request, $obj)
afterSave($request, $obj)
afterStore($request, $obj)
afterUpdate($request, $obj)
afterDestroy($request, $obj)
```

- Exemplo

```php
class ProjectsController extends CrudController
{
    public function __construct()
    {
    }

    protected function getModel()
    {
        return {MODEL}::class;
    }

    protected function applyFilters(Request $request, $query) {
        $query = $query->with('{relacionamento}');

        if($request->has('name'))
            $query = $query->where('name', 'like', '%'.$request->name.'%');
    }

    protected function beforeSearch(Request $request, $dataQuery, $countQuery) {
        $dataQuery->orderBy('name', 'asc');
    }

    protected function getValidationRules(Request $request, Model $obj)
    {
        $rules = [
            'name' => 'required|max:100|unique:{resource}'
        ];

        if ( strpos($request->route()->getName(), '{resource}.update') !== false ) {
            $rules['name'] = 'required|max:255|unique:{resource},name,'.$obj->id;
        }

        return $rules;
    }
}
```

> ### Formatação de atributos ###

Para formatar os atributos no lado do servidor, deve ser adicionado no array de cast no construtor do model
como no exemplo abaixo:

```php
public function __construct($attributes = array())
{
    parent::__construct($attributes);

    $this->addCast(['{atributo}' => '{formato}']);
}
```

Obs: Exceto para as datas que já são pré formatadas, podendo ocorrer erros caso o padrão seja modificado.

> ### Para fazer uma validação específica ###

Em qualquer action de um CrudController é possível adicionar validações específicas com o mesmo padrão de resposta esperado. 

```php
  $this->validate($request, []);

  if($objeto->owner_id !== Auth::id()) {
      $this->validator->errors()->add('owner', 'Este recurso não é seu');
      $this->throwValidationException($request, $this->validator);
  }
```