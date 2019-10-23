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
    "ecmaVersion": 2018,
    "ecmaFeatures": {
      "modules": false,
      "impliedStrict": false
    }
  },
  rules: {
    "strict": [2, "global"],
    "indent": ["error", 2],
    "linebreak-style": 0,
    "max-len": [2, 120, 2, {
      ignoreUrls: true,
      ignoreComments: false
    }],
    "comma-dangle": [2, 'never'],
    "no-restricted-syntax": [0],
    "no-multi-assign": 0,
    "no-return-assign": 0,
    "strict": [2, "global"],
    "global-require": 0,
    "padded-blocks": 0,
    "no-underscore-dangle": 0,
    "no-param-reassign": 0
  }
};