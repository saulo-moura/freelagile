## Repositórios ##

- Atualmente todo o código fonte está no repositório [Starter Pack PHP](http://git.prodeb.ba.gov.br/starter-pack/laravel_angular_base)
  - Dentro deste repositório existe uma git subtree montada no public/client com base no repositório [Starter Pack Angular](http://git.prodeb.ba.gov.br/starter-pack/starter-pack-angular-client)

## Trabalhando com a subtree ##

- Adicionando o repositório do front-end

```sh
git checkout develop
git remote add starter-pack-front-end git@git.prodeb.ba.gov.br:starter-pack/starter-pack-angular-client.git
```

- Atualizando a subtree com base no seu repositório

```sh
git checkout develop
git fetch starter-pack-front-end develop
git subtree pull --prefix public/client starter-pack-front-end develop --squash
```

- Enviando para o repositório do front-end as mudanças realizadas na subtree

```sh
git checkout develop
git subtree push --prefix=public/client/ starter-pack-front-end develop
# nesse comando o git pega todos os commits existentes desde o último envio, separa os arquivos
# que estão dentro da árvore e envia para o repositório do front-end
```