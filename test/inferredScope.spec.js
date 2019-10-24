'use strict';

const Hapi = require('@hapi/hapi');

const { expect } = require('@hapi/code');

const { describe, it } = exports.lab = require('@hapi/lab').script();

const setAuthSchemeWithScope = (scope) => () => ({
  authenticate(request, h) {
    return h.authenticated({ credentials: { scope } });
  }
});

describe('inferred scope', () => {

  it('authenticates on matching a grouped scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/groupedscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/groupedscope');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates on matching a grouped scope and explicit scopes exist', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope', 'scope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/inferredexplicit',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/inferredexplicit');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates on matching a single inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/singleinferred',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/singleinferred');
    expect(res.statusCode).to.equal(200);
  });

  it('builds scopeContext on matching a single inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/scopecontext',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/scopecontext');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope).to.exist();
  });

  it('authenticates and reduces extraneous scopes to common inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope', 'scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/reduces',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/reduces');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope).to.exist();
    expect(res.result.scopeContext.scope.subscope).to.not.exist();
  });

  it('authenticates on matching a twice nested inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/twicenested',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope1:subscope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/twicenested');
    expect(res.statusCode).to.equal(200);
  });

  it('builds scopeContext on matching a twice nested inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/twicenested',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope1:subscope2']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/twicenested');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope.subscope1).to.exist();
  });

  it('authenticates on matching a grouped scope on a twice nested inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/twicenested',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope1:subscope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/twicenested');
    expect(res.statusCode).to.equal(200);
  });

  it('builds scopeContext on matching a 3x nested inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/threetimesnested',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope1:subscope2']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/threetimesnested');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope.subscope1).to.exist();
    expect(res.result.scopeContext.scope.subscope1.subscope2).to.exist();
  });

  it('authenticates and reduces extraneous 3x grouped scopes to common inferred scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1', 'scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/threetimesnested',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope1']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/threetimesnested');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope).to.exist();
    expect(res.result.scopeContext.scope.subscope1).to.exist();
    expect(res.result.scopeContext.scope.subscope1.subscope2).to.not.exist();
  });

  it('builds scopeContext on inferred and explicit scopes', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1', 'scope1:subscope2', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/mixed',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope1:subscope1']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/mixed');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope1).to.exist();
    expect(res.result.scopeContext.scope1.subscope1).to.exist();
    expect(res.result.scopeContext.scope1.subscope2).to.exist();
    expect(res.result.scopeContext.scope2).to.exist();
  });

  it('builds scopeContext on inferred and explicit reduced scopes', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(
      ['scope1:subscope1', 'scope1:subscope2', 'scope2', 'scope2:subscope2']
    ));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/mixed',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope1:subscope1']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/mixed');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope1).to.exist();
    expect(res.result.scopeContext.scope1.subscope1).to.exist();
    expect(res.result.scopeContext.scope1.subscope2).to.exist();
    expect(res.result.scopeContext.scope2).to.exist();
    expect(res.result.scopeContext.scope2.subscope2).to.not.exist();
  });

  it('fails to authenticate when single group scope is too granular', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/invalidscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/invalidscope');
    expect(res.statusCode).to.equal(403);
  });

  it('fails to authenticate when multiple group scope is too granular', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/invalidscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:subscope1']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/invalidscope');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates a required scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticates when a required scope is missing', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates a required nested scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1:subscope1']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticates when a required nested scope is missing', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1:subscope1']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates a missing forbidden scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticates when a forbidden scope exists', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates a missing forbidden nested scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope:subscope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticates when a forbidden nested scope exists', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope:subscope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(403);
  });

  it('fails to authenticate an inferred scope where the route specifies a nested forbidden scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope:subscope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates an inferred scope where the route specifies a nested required scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope:subscope']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticate an inferred scope where the route specifies a twice nested forbidden scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/forbiddenscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['!scope:subscope1:subscope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/forbiddenscope');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates an inferred scope where the route specifies a twice nested required scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/requiredscope',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope:subscope1:subscope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/requiredscope');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates with a required scope and a missing forbidden scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/mixture',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1:subscope1', '!scope2:subscope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/mixture');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticates with an inferred required scope and a forbidden scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/mixture',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1:subscope1', '!scope2:subscope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/mixture');
    expect(res.statusCode).to.equal(403);
  });

  it('fails to authenticates with a required scope and an inferred forbidden scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/mixture',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1:subscope1', '!scope2:subscope2']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/mixture');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates with a required scope and a forbidden scope missing', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1', 'scope2:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/mixture',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['+scope1:subscope1', '!scope2:subscope3']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/mixture');
    expect(res.statusCode).to.equal(200);
  });

  it('dynamically binds request data to grouped scopes', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/groupedscope/{scope}/{subscope}',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['{params.scope}:{params.subscope}']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/groupedscope/scope/subscope');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope).to.exist();
    expect(res.result.scopeContext.scope.subscope).to.exist();
  });

  it('authenticates with a regex scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/regex',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['/.*/']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/regex');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates with a partial regex nested scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/regex',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:/sub.*/']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/regex');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates with a regex nested scope', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/regex',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['/.*/:/.*/']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/regex');
    expect(res.statusCode).to.equal(200);
  });

  it('fails to authenticate when a nested scope is missing', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/regex',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['/.*/']
        },
        handler: (request, h) => h.response().code(200)
      }
    });

    const res = await server.inject('/regex');
    expect(res.statusCode).to.equal(403);
  });

  it('authenticates using regex and dynamic scopes', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/groupedscope/{scope}/{subscope1}',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['{params.scope}:{params.subscope1}:/sub.*/']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/groupedscope/scope/subscope1');
    expect(res.statusCode).to.equal(200);
    expect(res.result.scopeContext).to.exist();
    expect(res.result.scopeContext.scope).to.exist();
    expect(res.result.scopeContext.scope.subscope1).to.exist();
    expect(res.result.scopeContext.scope.subscope1.subscope2).to.exist();
  });

  it('authenticates using a match all operator', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/matchall',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['*']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/matchall');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates using a match all operator when a subscope doesn\'t exist', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/matchall',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:*']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/matchall');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates using a nested match all operator', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/matchall',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:*']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/matchall');
    expect(res.statusCode).to.equal(200);
  });


  it('authenticates using a twice nested match all operator', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/matchall',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:*']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/matchall');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates using the first match all operator discovered', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/matchall',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['scope:*:*']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/matchall');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticates and ignores any scopes after the match all operator', async () => {
    const server = new Hapi.Server();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    await server.register(require('../'));

    server.route({
      method: 'GET',
      path: '/matchall',
      config: {
        auth: 'scope',
        plugins: {
          inferredScope: ['*:scope']
        },
        handler: (request, h) => h.response(request.auth.artifacts).code(200)
      }
    });

    const res = await server.inject('/matchall');
    expect(res.statusCode).to.equal(200);
  });
});
