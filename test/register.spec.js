'use strict';

const Hapi = require('@hapi/hapi');

const { expect } = require('@hapi/code');

const { describe, it } = exports.lab = require('@hapi/lab').script();

describe('register', () => {

  it('passes with default options', async () => {
    const server = new Hapi.Server();
    let exception = null;

    try {
      await server.register(require('../'));
    } catch (e) {
      exception = e;
    }

    expect(exception).to.be.null();
  });

  it('passes with configured options', async () => {
    const server = new Hapi.Server();

    const options = {
      scopeDelimiter: ';',
      scopeAccessor: (request) => request.auth.credentials.scope
    };

    let exception = null;
    try {
      await server.register({
        plugin: require('../'),
        options
      });
    } catch (e) {
      exception = e;
    }
    expect(exception).to.be.null();
  });

  it('fails with invalid options', async () => {
    const server = new Hapi.Server();

    const options = {
      invalidProperty: 'invalidProperty'
    };

    let exception = null;
    try {
      await server.register({
        plugin: require('../'),
        options
      });
    } catch (e) {
      exception = e;
    }
    expect(exception).to.not.be.null();
    expect(exception.message).to.equal('"invalidProperty" is not allowed');
  });

});
