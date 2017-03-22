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
`user`
`user:account`

We can now guard a route with the most specific scope we'd like a request auth credentials to have. 
For example, a route which accesses a user's account we can guard with `user:account`.
An auth credential that has scope `user:account` is allowed to access this route, along with any credential that has the parent scope `user` - this is inferred.

Like hapi scopes, we can still make scopes required `+` or forbidden `!` - however, we can take into consideration the inferring parent mechanism.
If we want to forbid a credential with scope `user:account` from accessing a particular route, we simply specify: `!user:account` on the route.
A credential that has scope `user` however, is still able to access the route.

Dynamic scopes using request data is also supported (again, like hapi), allowing scopes to be specified such as: `user:{params.accountType}`.

In addition, a `scopeContext` is created and accessible on `request.auth.arifacts.scopeContext`. This is an object representing the hierarchy of grouped scopes.
`scopeContext` can be inspected to make any further decisions regarding scopes during a request's life-cycle.
For example a credential with scopes: `['user:account:read', 'user:profile', 'admin']` will have the following `scopeContext`:

```javascript
{
  user: {
    account: {
      read
    },
    profile: {}
  },
  admin: {}
}
```

Note:
Due to the inferred nature of the scopes, a credential with scopes `['user', 'user:account']` will be reduced to `['user']` (as the `account` sub-scope is inferred).
To allow any scopes, simply assign `inferredScope: []`.