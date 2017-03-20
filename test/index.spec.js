'use strict';

const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');

const expect = Code.expect;
const lab = Lab.script();
const describe = lab.describe;
const it = lab.it;

describe('register', () => {

  it('passes with default options', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.register(require('../'), (err) => {
      expect(err).to.not.exist();
      done();
    });
  });

  it('passes with configured options', (done) => {
    const server = new Hapi.Server();
    server.connection();

    const options = {
      scopeDelimiter: ';',
      scopeAccessor: request => request.auth.credentials.scope
    };

    server.register({
      register: require('../'),
      options
    }, (err) => {
      expect(err).to.not.exist();
      done();
    });
  });

  it('fails with invalid options', (done) => {
    const server = new Hapi.Server();
    server.connection();

    const options = {
      invalidProperty: 'invalidProperty'
    };

    server.register({
      register: require('../'),
      options
    }, (err) => {
      expect(err).to.exist();
      done();
    });
  });

});
