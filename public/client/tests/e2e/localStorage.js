var LocalStorage = function () {
    this.setValue = function (key, object) {
        return browser.executeScript("return window.localStorage.setItem('" + key + "', '" + JSON.stringify(object) + "');");
    };

    this.getValue = function (key) {
        return browser.executeScript("return window.localStorage.getItem('" + key + "');");
    };

    this.get = function () {
        browser.executeScript("return window.localStorage;");
    };

    this.clear = function () {
        browser.executeScript("return window.localStorage.clear();");
    };
};

module.exports = new LocalStorage();
