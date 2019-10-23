'use strict';

const Hapi = require('@hapi/hapi');

const { expect } = require('@hapi/code');

const { describe, it } = exports.lab = require('@hapi/lab').script();

const setAuthSchemeWithScope = (scope) => () => ({
  authenticate(request, h) {
    return h.authenticated({ credentials: { scope } });
  }
});

describe('explicit scope', () => {

  it('assigns scopeContext to auth artifacts', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/artifacts',
      options: {
        auth: 'scope',
        plugins: {
          inferredScope: []
        },
        handler: (request) => request.auth.artifacts
      }
    });

    const res = await server.inject('/artifacts');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
  });

  it('builds scopeContext object', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/artifacts',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: []
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/artifacts');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope1).to.exist();
    expect(res.result.scopeContext.scope2).to.exist();
  });

  it('authenticates on matching an explicit single scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/singlescope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/singlescope');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates on matching explicit multiple scopes', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/multiplescopes',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope1', 'scope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/multiplescopes');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates on matching at least one explicit scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/eitherscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/eitherscope');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates when the route is configured with no scopes (empty array)', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/emptyscopes',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: []
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/emptyscopes');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates a required scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticates when a required scope is missing', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates a missing forbidden scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope1', 'scope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticates when a forbidden scope exists', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(403);
  });


  it('dynamically binds request data to scopes', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/groupedscope/{scope}',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['{params.scope}']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/groupedscope/scope');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope).to.exist();
  });

});
