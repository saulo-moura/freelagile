// spec.js

var helper = require('../helper');
var data = require('../data');
var localStorage = require("../localStorage")
var LoginPage = require('../login/login.page');
var UserPage = require('../users/users.page');

describe('Users Page', function() {
  var loginPage = new LoginPage();
  var usersPage = new UserPage();

  describe('normal user', function() {
    beforeAll(function() {
      loginPage.logout();
      loginPage.visit();
      loginPage.login({
        email: 'normal-base@prodeb.com'
      });
    });

    beforeEach(function() {
      usersPage.visit().then(function() {
        browser.sleep(1000);
      });
    })

    it('should not have access to users page', function() {
      expect(element(by.id('page-breadcrumb')).getText()).toEqual('Acesso Negado');
    });
  });

  describe('admin user', function() {

    var totalUsersWithSearchUsuarioCriteria = 2;

    beforeAll(function() {
      loginPage.logout();
      loginPage.visit();
      loginPage.login();
    });

    beforeEach(function() {
      usersPage.visit().then(function() {
        browser.sleep(1000);
      });
    })

    it('should visit users page', function() {
      expect(element(by.id('page-breadcrumb')).getText()).toEqual('Administração - Usuário');
    });

    it('should load users list', function() {
      expect(usersPage.resourcesList.count()).not.toBeLessThan(0);
    });

    it('should search users list', function() {
      usersPage.search('usuario');

      expect(usersPage.resourcesList.count()).not.toBeLessThan(0);

      usersPage.search(data.validAdminUser.email);

      expect(usersPage.resourcesList.count()).toBe(1);

      usersPage.search('strangenamewithnosense3413g2c4');

      expect(usersPage.resourcesList.count()).toBe(0);
    });

    it('shouldnt save new user with no data', function() {
      usersPage.save({
        name: '',
        email: ''
      });
      helper.expectToastToEqual('O campo Nome é obrigatório.\nO campo Email é obrigatório.');
    });

    it('should save new user with valid data', function() {
      usersPage.save();
      helper.expectToastToEqual('Registro salvo com sucesso.');
    });

    it('should update a user', function() {
      var updateEmail = 'udu9qnyu3g1iy3h1uyg@prodeb.ba.gov.br';

      //create a user to can update later
      usersPage.save({
        email: updateEmail
      });

      usersPage.update({
        name: 'Updated Name',
        email: updateEmail
      });

      browser.sleep(1000);
      helper.expectToastToEqual('Registro salvo com sucesso.');

      //get user list and try to find user's mail saved
      var userFound = usersPage.findUserByEmailInList(updateEmail);

      expect(userFound).toBeDefined();
    });

    it('should remove a user', function() {
      usersPage.resourcesList.count().then(function(count) {
        var email = '83y1uon3y1t3971h3nyu1g@prodeb.ba.gov.br';

        //create a user to can remove later
        usersPage.save({
          email: email
        });

        usersPage.remove(email);

        helper.expectToastToEqual('Remoção realizada com sucesso.');

        //should be the same total, because create a new and removed them
        expect(usersPage.resourcesList.count()).toBe(count);
      });
    });

  });

});
