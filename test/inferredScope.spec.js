'use strict';

const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');

const expect = Code.expect;
const lab = Lab.script();
const describe = lab.describe;
const it = lab.it;

const setAuthSchemeWithScope = (scope) =>
  () => ({
    authenticate(request, reply) {
      return reply.continue({ credentials: { scope } });
    }
  });

describe('inferred scope', () => {

  it('authenticates on matching a grouped scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/groupedscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/groupedscope', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates on matching a grouped scope and explicit scopes exist', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope', 'scope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/inferredexplicit',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/inferredexplicit', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates on matching a single inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/singleinferred',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/singleinferred', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('builds scopeContext on matching a single inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/scopecontext',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/scopecontext', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope).to.exist();
        done();
      });
    });
  });

  it('authenticates and reduces extraneous scopes to common inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope', 'scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/reduces',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/reduces', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope).to.exist();
        expect(res.result.scopeContext.scope.subscope).to.not.exist();
        done();
      });
    });
  });

  it('authenticates on matching a twice nested inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/twicenested',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope1:subscope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/twicenested', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('builds scopeContext on matching a twice nested inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/twicenested',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope1:subscope2']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/twicenested', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope.subscope1).to.exist();
        done();
      });
    });
  });

  it('authenticates on matching a grouped scope on a twice nested inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/twicenested',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope1:subscope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/twicenested', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('builds scopeContext on matching a 3x nested inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/threetimesnested',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope1:subscope2']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/threetimesnested', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope.subscope1).to.exist();
        expect(res.result.scopeContext.scope.subscope1.subscope2).to.exist();
        done();
      });
    });
  });

  it('authenticates and reduces extraneous 3x grouped scopes to common inferred scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1', 'scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/threetimesnested',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope1']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/threetimesnested', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope).to.exist();
        expect(res.result.scopeContext.scope.subscope1).to.exist();
        expect(res.result.scopeContext.scope.subscope1.subscope2).to.not.exist();
        done();
      });
    });
  });

  it('builds scopeContext on inferred and explicit scopes', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1', 'scope1:subscope2', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/mixed',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope1:subscope1']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/mixed', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope1).to.exist();
        expect(res.result.scopeContext.scope1.subscope1).to.exist();
        expect(res.result.scopeContext.scope1.subscope2).to.exist();
        expect(res.result.scopeContext.scope2).to.exist();
        done();
      });
    });
  });

  it('builds scopeContext on inferred and explicit reduced scopes', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(
      ['scope1:subscope1', 'scope1:subscope2', 'scope2', 'scope2:subscope2'])
    );
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/mixed',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope1:subscope1']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/mixed', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope1).to.exist();
        expect(res.result.scopeContext.scope1.subscope1).to.exist();
        expect(res.result.scopeContext.scope1.subscope2).to.exist();
        expect(res.result.scopeContext.scope2).to.exist();
        expect(res.result.scopeContext.scope2.subscope2).to.not.exist();
        done();
      });
    });
  });

  it('fails to authenticate when single group scope is too granular', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/invalidscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/invalidscope', (res) => {
        expect(res.statusCode).to.equal(403);
        done();
      });
    });
  });

  it('fails to authenticate when multiple group scope is too granular', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/invalidscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:subscope1']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/invalidscope', (res) => {
        expect(res.statusCode).to.equal(403);
        done();
      });
    });
  });

  it('authenticates a required scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope']
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

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope']
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

  it('authenticates a required nested scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1:subscope1']
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

  it('fails to authenticates when a required nested scope is missing', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1:subscope1']
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

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope']
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

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope']
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

  it('authenticates a missing forbidden nested scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope([]));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope:subscope']
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

  it('fails to authenticates when a forbidden nested scope exists', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope:subscope']
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

  it('fails to authenticate an inferred scope where the route specifies a nested forbidden scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope:subscope']
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

  it('authenticates an inferred scope where the route specifies a nested required scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope:subscope']
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

  it('fails to authenticate an inferred scope where the route specifies a twice nested forbidden scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/forbiddenscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['!scope:subscope1:subscope2']
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

  it('authenticates an inferred scope where the route specifies a twice nested required scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/requiredscope',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope:subscope1:subscope2']
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

  it('authenticates with a requied scope and a missing forbidden scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/mixture',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1:subscope1', '!scope2:subscope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/mixture', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('fails to authenticates with an inferred required scope and a forbidden scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1', 'scope2:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/mixture',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1:subscope1', '!scope2:subscope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/mixture', (res) => {
        expect(res.statusCode).to.equal(403);
        done();
      });
    });
  });

  it('fails to authenticates with a required scope and an inferred forbidden scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1', 'scope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/mixture',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1:subscope1', '!scope2:subscope2']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/mixture', (res) => {
        expect(res.statusCode).to.equal(403);
        done();
      });
    });
  });

  it('authenticates with a required scope and a forbidden scope missing', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope1:subscope1', 'scope2:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/mixture',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['+scope1:subscope1', '!scope2:subscope3']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/mixture', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('dynamically binds request data to grouped scopes', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/groupedscope/{scope}/{subscope}',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['{params.scope}:{params.subscope}']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/groupedscope/scope/subscope', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope).to.exist();
        expect(res.result.scopeContext.scope.subscope).to.exist();
        done();
      });
    });
  });

  it('authenticates with a regex scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/regex',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['/.*/']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/regex', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates with a partial regex nested scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/regex',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:/sub.*/']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/regex', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates with a regex nested scope', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/regex',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['/.*/:/.*/']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/regex', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('fails to authenticate when a nested scope is missing', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/regex',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['/.*/']
          },
          handler: (request, reply) => reply().code(200)
        }
      });

      server.inject('/regex', (res) => {
        expect(res.statusCode).to.equal(403);
        done();
      });
    });
  });

  it('authenticates using regex and dynamic scopes', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/groupedscope/{scope}/{subscope1}',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['{params.scope}:{params.subscope1}:/sub.*/']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/groupedscope/scope/subscope1', (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.result.scopeContext).to.exist();
        expect(res.result.scopeContext.scope).to.exist();
        expect(res.result.scopeContext.scope.subscope1).to.exist();
        expect(res.result.scopeContext.scope.subscope1.subscope2).to.exist();
        done();
      });
    });
  });

  it('authenticates using a match all operator', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/matchall',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['*']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/matchall', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates using a match all operator when a subscope doesn\'t exist', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/matchall',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:*']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/matchall', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates using a nested match all operator', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/matchall',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:*']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/matchall', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates using a twice nested match all operator', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1:subscope2']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/matchall',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:*']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/matchall', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates using the first match all operator discovered', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope:subscope1']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/matchall',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['scope:*:*']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/matchall', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  it('authenticates and ignores any scopes after the match all operator', (done) => {
    const server = new Hapi.Server();
    server.connection();

    server.auth.scheme('scopeTest', setAuthSchemeWithScope(['scope']));
    server.auth.strategy('scope', 'scopeTest');

    server.register(require('../'), () => {

      server.route({
        method: 'GET',
        path: '/matchall',
        config: {
          auth: 'scope',
          plugins: {
            inferredScope: ['*:scope']
          },
          handler: (request, reply) => reply(request.auth.artifacts).code(200)
        }
      });

      server.inject('/matchall', (res) => {
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

});
