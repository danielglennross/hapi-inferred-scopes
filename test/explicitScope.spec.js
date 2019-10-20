'use strict';

const Hapi = require('hapi');

const { expect } = require('code');
const { describe, it } = exports.lab = require('lab').script();

const setAuthSchemeWithScope = (scope) =>
  () => ({
    authenticate(request, reply) {
      return reply.continue({ credentials: { scope } });
    }
  });

describe('explicit scope', () => {

  it('assigns scopeContext to auth artifacts', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/artifacts',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: []
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/artifacts', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        done();
      });
    });
  });

  it('builds scopeContext object', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/artifacts',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: []
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/artifacts', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope1).to.exist();
        expect(res.result.scopeContext.scope2).to.exist();
        done();
      });
    });
  });

  it('authenticates on matching an explicit single scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/singlescope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/singlescope', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates on matching explicit multiple scopes', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/multiplescopes',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope1', 'scope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/multiplescopes', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates on matching at least one explicit scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/eitherscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/eitherscope', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates when the route is configured with no scopes (empty array)', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/emptyscopes',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: []
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/emptyscopes', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates a required scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/requiredscope', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('fails to authenticates when a required scope is missing', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/requiredscope', (res) => {
        expect(res.statusCode).to.equal(403);
        done();
      });
    });
  });

  it('authenticates a missing forbidden scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope1', 'scope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/forbiddenscope', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('fails to authenticates when a forbidden scope exists', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/forbiddenscope', (res) => {
        expect(res.statusCode).to.equal(403);
        done();
      });
    });
  });

  it('dynamically binds request data to scopes', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/groupedscope/{scope}',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['{params.scope}']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/groupedscope/scope', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope).to.exist();
        done();
      });
    });
  });

});
