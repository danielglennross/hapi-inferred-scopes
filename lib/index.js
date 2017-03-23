'use strict';

const deep = require('deep-get-set');
const Boom = require('boom');
const Joi = require('joi');

const internals = {};

internals.schema = Joi.object({
  scopeDelimiter: Joi.string().default(':'),
  scopeAccessor: Joi.func().default(request => request.auth.credentials.scope)
});

internals.isSegRegex = s => s.startsWith('/') && s.endsWith('/');

internals.isScope2Inferred = (scope1, scope2, delimiter) => {
  const scope1Segs = scope1.split(delimiter);
  const scope2Segs = scope2.split(delimiter);
  const zip = scope1Segs.map((s1Seg, i) => [s1Seg, scope2Segs[i]]);
  const match = zip.filter(z => {
    const seg2Exists = z[1];
    const defferedSegsAreEqual = () => (
      internals.isSegRegex(z[0])
      ? new RegExp(z[0].slice(1, -1)).test(z[1])
      : z[0] === z[1]
    );
    return seg2Exists && defferedSegsAreEqual();
  });
  return match.map(m => m[1]).join(delimiter) === scope2;
};

internals.getEffectiveScopes = (scopes, settings) => {
  const effectiveScopes = scopes.reduce((es, s1) => {
    const inferredExists = scopes.some(s2 =>
      s1 !== s2 && internals.isScope2Inferred(s1, s2, settings.scopeDelimiter)
    );

    if (!inferredExists) {
      es.push(s1);
    }

    return es;
  }, []);

  return effectiveScopes;
};

internals.hasInferredScope = (request, effectiveScopes, settings) => {
  const rScopes = [...request.route.settings.plugins.inferredScope];
  const delimiter = settings.scopeDelimiter;

  const computeScope = (seg) => {
    if (internals.isSegRegex(seg)) {
      return seg;
    }

    const matches = seg.match(/{(.*)}/g) || [];
    const cleaned = matches.reduce((pr, pattern) => {
      const result = deep(request, pattern.replace('{', '').replace('}', ''));
      pr.push({ pattern, result });
      return pr;
    }, []);

    const computed = cleaned.reduce(
      (c, { pattern, result }) => c.replace(pattern, result), seg
    );

    return computed;
  };

  rScopes.forEach((rs) => {
    const computedScope = rs.split(delimiter).map(computeScope).join(delimiter);
    rScopes[rScopes.indexOf(rs)] = computedScope;
  });

  const scopesEqualOrInferred = s1 => effectiveScopes.some(s2 =>
    s1 === s2 || internals.isScope2Inferred(s1, s2, settings.scopeDelimiter)
  );
  const scopesNotEqualOrNotInferred = s1 => effectiveScopes.every(s2 =>
    s1 !== s2 || !internals.isScope2Inferred(s1, s2, settings.scopeDelimiter)
  );

  const required = rScopes.filter(r => r.startsWith('+')).map(s => s.slice(1));
  const requiredMatch = required.length
    ? required.every(scopesEqualOrInferred)
    : true;

  const forbidden = rScopes.filter(r => r.startsWith('!')).map(s => s.slice(1));
  const forbiddenMatch = forbidden.length
    ? forbidden.every(scopesNotEqualOrNotInferred)
    : true;

  const either = rScopes.filter(r => !(r.startsWith('+') || r.startsWith('!')));
  const eitherMatch = either.length
    ? either.some(scopesEqualOrInferred)
    : true;

  return requiredMatch && forbiddenMatch && eitherMatch;
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
    // eslint-disable-next-line no-param-reassign
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
  return next();
};

exports.register.attributes = {
  name: 'hapi-inferred-scopes',
  version: '1.0.0'
};
