'use strict';

const deep = require('deep-get-set');
const Boom = require('boom');
const Joi = require('joi');

const internals = {};

internals.schema = Joi.object({
  scopeDelimiter: Joi.string().default(':'),
  scopeAccessor: Joi.func().default(request => request.auth.credentials.scope)
});

internals.isScope2Inferred = (scope1, scope2, delimiter, cleanFunc = s => s) => {
  const scope1Segs = scope1.split(delimiter).map(cleanFunc);
  const scope2Segs = scope2.split(delimiter).map(cleanFunc);
  const zip = scope1Segs.map((s1Seg, i) => [s1Seg, scope2Segs[i]]);
  const match = zip.filter(z => z[0] === z[1]);
  const suggestedInfer = match.map(m => m[1]).join(delimiter);
  return suggestedInfer === scope2 ? scope2 : false;
};

internals.getEffectiveScopes = (scopes, settings) => {
  const delimiter = settings.scopeDelimiter;

  const effectiveScopes = scopes.reduce((es, s1) => {
    const inferredExists = scopes.some(s2 =>
      s1 !== s2 && internals.isScope2Inferred(s1, s2, delimiter)
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
      const result = deep(request, pattern.replace('{', '').replace('}', ''));
      pr.push({ pattern, result });
      return pr;
    }, []);

    const computed = cleaned.reduce(
      (c, { pattern, result }) => c.replace(pattern, result), rs
    );
    rScopes[rScopes.indexOf(rs)] = computed;
  });

  const delimiter = settings.scopeDelimiter;

  // eslint-disable-next-line
  const cleanSeg = s => (s.startsWith('+') || s.startsWith('!') ? s = s.slice(1) : s);

  const inferredScopes = rScopes.reduce((m, s1) => {
    effectiveScopes.forEach(s2 => {
      const match = internals.isScope2Inferred(s1, s2, delimiter, cleanSeg);
      if (match) {
        m.push(match);
      }
    });
    return m;
  }, []);

  const filterRouteScopesBy = c => rScopes.filter(
    s => s.split(delimiter).some(seg => seg.startsWith(c))
  );

  const clean = (s, c) =>
    s.split(delimiter).map(m => m.replace(c, '')).join(delimiter);

  const forbidden = filterRouteScopesBy('!');
  const fMatch = forbidden.length
    ? forbidden.every(
        f => inferredScopes.every(is => clean(f, '!') !== is)
      )
    : true;

  const required = filterRouteScopesBy('+');
  const rMatch = required.length
    ? required.some(
        r => inferredScopes.some(
          is => internals.isScope2Inferred(clean(r, '+'), is, delimiter, cleanSeg)
        )
      )
    : true;

  return !!inferredScopes.length && fMatch && rMatch;
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
  next();
};

exports.register.attributes = {
  name: 'hapi-inferred-scopes',
  version: '1.0.0'
};
