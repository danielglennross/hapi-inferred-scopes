'use strict';

const deep = require('deep-get-set');
const Boom = require('@hapi/boom');
const Joi = require('@hapi/joi');

const internals = {};

internals.schema = Joi.object({
  scopeDelimiter: Joi.string().default(':'),
  scopeAccessor: Joi.function()
});

internals.isSegMatchAll = (s) => s === '*';

internals.isSegRegex = (s) => s.startsWith('/') && s.endsWith('/');

internals.segmentProcessingCommands = {
  isRegex: {
    test: internals.isSegRegex,
    process: (seg) => seg
  },
  isMatchAll: {
    test: internals.isSegMatchAll,
    process: (seg) => seg
  },
  isComputable: {
    test: (seg) => !(internals.isSegRegex(seg) || internals.isSegMatchAll(seg)),
    process: (seg, request) => {
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
    }
  }
};

internals.isScope2Inferred = (scope1, scope2, delimiter) => {
  const scope1Segs = scope1.split(delimiter);
  const scope2Segs = scope2.split(delimiter);

  let effectiveScope2 = scope2;
  let zip = scope1Segs.map((s1Seg, i) => [s1Seg, scope2Segs[i]]);

  if (internals.isSegMatchAll(zip[zip.length - 1][0])) {
    zip = zip.slice(0, -1);
    effectiveScope2 = zip.map((_, i) => scope2Segs[i]).join(delimiter);
  }

  const match = zip.filter((z) => {
    const seg2Exists = z[1];
    const deferredSegsAreEqual = () => (
      internals.isSegRegex(z[0])
        ? new RegExp(z[0].slice(1, -1)).test(z[1])
        : z[0] === z[1]
    );
    return seg2Exists && deferredSegsAreEqual();
  });

  return match.map((m) => m[1]).join(delimiter) === effectiveScope2;
};

internals.getEffectiveScopes = (scopes, settings) => {
  const effectiveScopes = scopes.reduce((es, s1) => {
    const inferredExists = scopes.some(
      (s2) => s1 !== s2 && internals.isScope2Inferred(s1, s2, settings.scopeDelimiter)
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

  const filters = {
    required: rScopes.filter((r) => r.startsWith('+')).map((s) => s.slice(1)),
    forbidden: rScopes.filter((r) => r.startsWith('!')).map((s) => s.slice(1)),
    optional: rScopes.filter((r) => !(r.startsWith('+') || r.startsWith('!')))
  };

  const ensureOnlyOneMatchAll = (segs) => {
    if (!segs.some(internals.isSegMatchAll)) {
      return segs;
    }

    const firstMatchAll = segs.find(internals.isSegMatchAll);
    return segs.filter((_, i) => i <= segs.indexOf(firstMatchAll));
  };

  Object.keys(filters).forEach((type) => (
    filters[type] = filters[type].map((rs) => ensureOnlyOneMatchAll(rs.split(delimiter))
      .map((seg) => {
        const commands = internals.segmentProcessingCommands;
        const command = Object.keys(commands).find((key) => commands[key].test(seg));
        return commands[command].process(seg, request);
      })
      .join(delimiter))
  ));

  const scopesEqualOrInferred = (s1) => effectiveScopes.some(
    (s2) => s1 === s2 || internals.isScope2Inferred(s1, s2, settings.scopeDelimiter)
  );

  const requiredMatch = filters.required.length
    ? filters.required.every(scopesEqualOrInferred)
    : true;

  const forbiddenMatch = filters.forbidden.length
    ? !filters.forbidden.every(scopesEqualOrInferred)
    : true;

  const optionalMatch = filters.optional.length
    ? filters.optional.some(scopesEqualOrInferred)
    : true;

  return requiredMatch && forbiddenMatch && optionalMatch;
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

internals.inferredScope = (settings) => (request, h) => {
  const inferredScopeConfig = request.route.settings.plugins.inferredScope;

  if (!inferredScopeConfig) {
    return h.continue;
  }

  const scope = settings.scopeAccessor(request);
  if (!scope) {
    return Boom.forbidden('Insufficient scope');
  }

  if (!(inferredScopeConfig instanceof Array)) {
    return Boom.forbidden('Unknown scopes');
  }

  const effectiveScopes = internals.getEffectiveScopes(scope, settings);

  request.auth.artifacts = request.auth.artifacts || {};
  request.auth.artifacts.scopeContext = internals.createScopeContext(
    effectiveScopes,
    settings
  );

  if (!internals.hasInferredScope(request, effectiveScopes, settings)) {
    return Boom.forbidden('Insufficient scope');
  }

  return h.continue;
};

exports.plugin = {
  register: (server, options) => {
    const validatedOptions = Joi.attempt(options, internals.schema);
    if (!validatedOptions.scopeAccessor) {
      validatedOptions.scopeAccessor = (request) => request.auth.credentials.scope;
    }
    server.ext('onPostAuth', internals.inferredScope(validatedOptions));
  },
  pkg: require('../package.json')
};
