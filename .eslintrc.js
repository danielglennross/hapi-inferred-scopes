module.exports = {
  extends: [
    'eslint-config-airbnb-base',
    'eslint-config-airbnb-base/rules/strict'
  ],
  "env": {
    "node": true
  },
  "parserOptions": {
    "sourceType": "script",
    "ecmaFeatures": {
      "modules": false,
      "impliedStrict": false
    }
  },
  rules: {
    "max-len": [2, 120, 2, {
      ignoreUrls: true,
      ignoreComments: false
    }],
    "comma-dangle": [2, 'never'],
    "no-restricted-syntax": [0],
    "strict": [2, "global"],
    "global-require": 0,
    "padded-blocks": 0,
    "no-underscore-dangle": 0
  }
};