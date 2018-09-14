# hapi-inferred-scopes

Hapi out-the-box scopes are powerful, but what if we wanted to manage scopes like resources which have sub-resources and infer whether a request is permitted?
`hapi-inferred-scopes` allows us to mark routes with finely grained scopes, however still permit access for credentials that infer parent scopes.

## Install

`npm install --save hapi-inferred-scopes`

## Usage

```javascript
// the following option values are the defaults
const options = {
  // how scopes / sub-scopes are delimited (e.g. user:account)
  scopeDelimiter: ':',
  // where we can find the auth credential's scope
  scopeAccessor: request => request.auth.credentials.scope
};

server.register({
  register: require('hapi-inferred-scopes'),
  options
}, (err) => {

  server.route({
    method: 'GET',
    path: '/user/email',
    config: {
      auth: 'session',
      plugins: {
        inferredScope: ['user:email'] // make this as granular as possible
      },
      handler: (request, reply) =>
        reply(request.auth.artifacts.scopeContext).code(200)
    }
  });

});
```

## Example

Say within our app we identify the following scope groups:

- `user`
- `user:account`

We can now guard a route with the most specific scope we'd like a request auth credentials to have.
For example, a route which accesses a user's account we can guard with `user:account`.
An auth credential that has scope `user:account` is allowed to access this route, along with any credential that has the parent scope `user` - this is inferred.

Like hapi scopes, we can still make scopes required `+` or forbidden `!` - however, we can take into consideration the inferring parent mechanism.
If we want to forbid a credential with scope `user:account` from accessing a particular route, we simply specify: `!user:account` on the route.
A credential that has scope `user` however, is still able to access the route.

Scope segments can also be dynamic expressions that refer to request data (again, like hapi), regular expressions or wild card operators.
At this time, dynamic expressions, regular expressions and wild card operators cannot be mixed and matched - they are exclusive.

For dynamic expressions, surround the expression in `{...}` like so:

- `{params.username`
- `user-{params.username}`
- `user:{params.accountType}`(child scope is a dynamic expression)

For regular expressions, surround the expression in `/.../` like so:

- `/.*/`
- `/user-.*/`
- `user:/.*/` (child scope is a regular expression)

A wild card operator: match all `*` is supported.
This operator will match any scope or subsequent sub-scopes, including absent ones. For example, `user:*` will match:

- `user`
- `user:account`
- `user:account:email` etc.

In addition, a `scopeContext` is created and accessible on `request.auth.artifacts.scopeContext`. This is an object representing the hierarchy of grouped scopes.
`scopeContext` can be inspected to make any further decisions regarding scopes during a request's life-cycle.
For example a credential with scopes: `['user:account:read', 'user:profile', 'admin']` will have the following `scopeContext`:

```javascript
{
  user: {
    account: {
      read: {}
    },
    profile: {}
  },
  admin: {}
}
```

Note:

- Due to the inferred nature of the scopes, a credential with scopes `['user', 'user:account']` will be reduced to `['user']` (as the `account` sub-scope is inferred).
- To allow any scopes, simply assign `inferredScope: []`.