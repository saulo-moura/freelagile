// spec.js

var helper = require('../helper');
var data = require('../data');
var LoginPage = require('./login.page');

describe('Login Page', function() {
  var page = new LoginPage();

  beforeEach(function() {
    page.visit();
  });

  describe('user', function() {
    it('should require login and email', function() {
      browser.sleep(1000); //sleep because inital info toast

      page.login({
        password: '',
        email: ''
      });

      helper.expectToastToEqual('O campo Email é obrigatório.\nO campo Senha é obrigatório.');
    });

    it('shouldn\'t authenticated with invalid credentials', function() {
      browser.sleep(1000); //sleep because inital info toast

      page.login({
        password: 'SenhaInvalida'
      });

      helper.expectToastToEqual('Credenciais Inválidas');
    });

    it('when try access authenticated page should be redirected to login page if not logged in', function() {
      browser.get(data.domain + 'app/usuario');

      expect(browser.getCurrentUrl()).toMatch(page.loginUrl);
    });

    it('should authenticated with valid credentials', function() {
      page.login();

      //check the shown email
      expect(element(by.id('logged-user-mail')).getText()).toEqual(data.validAdminUser.email);
    });
  });
});
