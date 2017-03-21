'use strict';

const Deep = require('deep-get-set');
const Boom = require('boom');
const Joi = require('joi');

const internals = {};

internals.schema = Joi.object({
  scopeDelimiter: Joi.string().default(':'),
  scopeAccessor: Joi.func().default(request => request.auth.credentials.scope)
});

internals.getEffectiveScopes = (scopes, settings) => {
  const delimiter = settings.scopeDelimiter;
  
  const isScope2Inferred = (scope1, scope2) => {
    const scope1Segs = scope1.split(delimiter);
    const scope2Segs = scope2.split(delimiter);
    const zip = scope1Segs.map((s1Seg, i) => [s1Seg, scope2Segs[i]]);
    const match = zip.filter(z => z[0] === z[1]);
    return match.map(m => m[1]).join(delimiter) === scope2;
  };
  
  const effectiveScopes = scopes.reduce((es, s1) => {
    const inferredExists = scopes.some(s2 =>
      s1 !== s2 && isScope2Inferred(s1, s2)
    );

    if (!inferredExists) {
      es.push(s1);
    }

    return es;
  }, []);

  return effectiveScopes;
};

internals.hasInferredScope = (request, effectiveScopes, settings) => {
  const rScopes = request.route.settings.plugins.inferredScope.slice(0);
  if (!rScopes.length) {
    return true;
  }

  rScopes.forEach((rs) => {
    const matches = rs.match(/{(.*?)}/g) || [];
    const cleaned = matches.reduce((pr, pattern) => {
      const result = Deep(request, pattern.replace('{', '').replace('}', ''));
      pr.push({ pattern, result });
      return pr;
    }, []);

    const computed = cleaned.reduce(
      (c, { pattern, result }) => c.replace(pattern, result), rs
    );
    rScopes[rScopes.indexOf(rs)] = computed;
  });

  const delimiter = settings.scopeDelimiter;

  const isScope2Inferred = (scope1, scope2) => {
    const scope1Segs = scope1.split(delimiter).map(s => 
      (s.startsWith('+') || s.startsWith('!') ? s = s.slice(1) : s)
    );
    const scope1Type = scope1.split(delimiter).map(s => {
      switch (s[0]) {
        case '+': return 'required';
        case '!': return 'forbidden';
        default : return;
      }
    });
    const scope2Segs = scope2.split(delimiter);
    const zip = scope1Type.map((s1Type, i) => [s1Type, scope1Segs[i], scope2Segs[i]]);

    // const isConditionTypeMet = zip.every(z => {
    //   if (z[0] === 'required') {
    //     return z[1] === z[2];
    //   }
    //   if (z[0] === 'forbidden') {
    //     return z[1] !== z[2];
    //   }
    //   return true;
    // });

    const match = zip.filter(z => z[1] === z[2]);
    return /*isConditionTypeMet &&*/ match.map(m => m[2]).join(delimiter) === scope2;
  };

  const neg = rScopes.some(s => s.split(delimiter).some(seg => seg.startsWith('!')))
  const plu = rScopes.some(s => s.split(delimiter).some(seg => seg.startsWith('+')))

  let condition;
  if (neg && !plu) condition = 'every';
  else condition = 'some';

  //const condition = rScopes.some(s => s.split(delimiter).some(seg => seg.startsWith('!'))) ? 'every' : 'some'

  const isScopeMet = rScopes.some(s1 => 
    effectiveScopes[condition](s2 => isScope2Inferred(s1, s2))
  );

  return isScopeMet;
};

internals.createScopeContext = (effectiveScopes, settings) => {
  const map = (s, o) => {
    if (s[0]) {
      if (!o[s[0]]) {
        Object.assign(o, { [s[0]]: {} });
      }
      const prev = s.shift();
      map(s, o[prev]);
    }
  };

  const scopeContext = effectiveScopes.reduce((sc, s) => {
    map(s.split(settings.scopeDelimiter), sc);
    return sc;
  }, {});

  return scopeContext;
};

internals.inferredScope = (settings) =>
  (request, reply) => {
    const inferredScopeConfig = request.route.settings.plugins.inferredScope;

    if (!inferredScopeConfig) {
      return reply.continue();
    }

    const scope = settings.scopeAccessor(request);
    if (!scope) {
      return reply(Boom.forbidden('Insufficient scope'));
    }

    if (!(inferredScopeConfig instanceof Array)) {
      return reply(Boom.forbidden('Unknown scopes'));
    }

    const effectiveScopes = internals.getEffectiveScopes(scope, settings);

    // eslint-disable-next-line no-param-reassign
    request.auth.artifacts = request.auth.artifacts || {};

    request.auth.artifacts.scopeContext = internals.createScopeContext(
      effectiveScopes,
      settings
    );

    if (!internals.hasInferredScope(request, effectiveScopes, settings)) {
      return reply(Boom.forbidden('Insufficient scope'));
    }

    return reply.continue();
  };

exports.register = (plugin, options, next) => {
  const results = Joi.validate(options, internals.schema);
  if (results.error) {
    return next(results.error);
  }

  plugin.ext('onPostAuth', internals.inferredScope(results.value));
  next();
};

exports.register.attributes = {
  name: 'hapi-inferred-scopes',
  version: '1.0.0'
};
