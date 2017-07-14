# ngProdeb #

## Sobre ##

Biblioteca de componetes angular da Prodeb

## Pré Requisito ##

- nodejs ^v4.*
- npm ^3.*
- bower (versão mais atual)
- gulp ^3.*

## Dependências ##

- angular
- angular-material
- lodash
- moment
- mdDatepicker
- angular file upload
- alasql
- xlsx

## Instalação ##

1- Baixe a biblioteca via bower

```sh
cd {pasta-do-projeto}
bower install 'git@git.prodeb.ba.gov.br:starter-pack/ngprodeb.git' --save
```

2- Carregue o javascript e css

```html
<link rel="stylesheet" href="bower_componentes/ng-prodeb/dist/ng-prodeb.min.css">
<script src="bower_componentes/ng-prodeb/dist/ng-prodeb.min.js"></script>
```

3- Inclua o ngProdeb como dependência na sua aplicação

```javascript
var app = angular.module('app', ['ngProdeb']);
```

4- Adicione os javascripts e css das dependências no arquivo gulpfile.js do seu projeto (foram instaladas pelo bower)

## Uso ##

Veja exemplos de uso em  \example\index.html

## Diretivas ##

**Paginação**

```html
<pr-pagination paginator="{paginatorInstance}"></pr-pagination>
```

**Spinner**

```html
<pr-spinner
  bg-color="{colorName}"
  text-color="{colorName}">
</pr-spinner>
```

**Datapicker**

```html
<pr-date-time-picker
  ng-model="{model}"
  placeholderDate="{string}"
  placeholderTime="{string}"
  formatTime="{HH:mm A}"
  min-date="{date}" //ex: 2016-10-10 ou 11-02-2016
  max-date="{date}" //ex: 2016-10-10 ou 11-02-2016
  date-filter="{functionFilter}"
  disabled-date="{boolean}"
  disabled-time="{boolean}"
  open-on-click="{boolean}"
  with-time="{boolean}"
  auto-switch="{boolean}">
</pr-date-time-picker>
```

> Para mais informações acesse [mdPickers](https://github.com/alenaksu/mdPickers)

**Uploader Base64**

```html
<input type="file" pr-uploader-base64 ng-model="{{model}}" aria-label="{string}"/>
```

## Serviços ##

- PrPagination
- PrSpinner
- PrToast
- PrDialog
- FileUploader
 
> obs.: o PrDialog usa as mesmas opções de configuração do serviço $mdDialog do angular-material,
para mais informações consulte: [Angular Material](https://material.angularjs.org/latest/api/service/$mdDialog)

**PrFile**

```javascript

var cars = [
 { name: 'Stilo',  brand: 'Fiat', date: moment().subtract(1, 'years') },
 { name: 'Punto',  brand: 'Fiat', date: moment().subtract(3, 'years') },
 { name: 'Fiesta', brand: 'Ford', date: '04-01-2017' }
]

PrFile.exportToExcel([
 { name: 'brand', label: 'Marca' },
 { name: 'name', label: 'Nome' },
 { name: 'formatDate(date, \'DD-MM-YYYY\')', label: 'Comprado em?' }
], cars, 'data-export', {
 orderBy: 'brand ASC, name ASC',
 where: 'brand like "%Fi%"'
});

```

## Icones Adicionados ##

```html
  <md-icon md-svg-icon="pr-excel"></md-icon>
```

## Angular File Upload ##

### Principais Diretivas ###

- nv-file-drop
- nv-file-over
- uploader
- over-class
- nv-file-select

> para mais informações sobre o uso do modulo acesse [Angular File Upload](https://github.com/nervgh/angular-file-upload)

## Para contribuir ##

- Instale o node e npm;
- Faça o clone do projeto;
- rode os comandos a seguir dentro da pasta do projeto clonado

```sh
cd {pasta-do-projeto}
npm install -g gulp bower eslint eslint-plugin-angular
npm install
npm run build
```

- Para rodar os exemplos, rode os comandos abaixos em outra aba do terminal/cmd;

```sh
cd {pasta-do-projeto}
npm run server
```
- Abra o navegador no link **http://localhost:5005/example**

