const base = require('./.commitlintrc.json');

module.exports = {
  ...base,
  rules: {
    ...base.rules,
    'type-enum': [2, 'always', ['chore']],
    'scope-enum': [2, 'always', ['main']],
    'body-empty': [0],
    'body-min-length': [0],
    'body-leading-blank': [0],
  },
};
