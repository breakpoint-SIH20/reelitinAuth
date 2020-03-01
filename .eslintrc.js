module.exports = {
    extends: ['prettier', 'eslint:recommended'],
    plugins: ['prettier'],
    parser: 'esprima',
    env: {
        node: true,
        commonjs: true,
        es6: true,
    },
    parserOptions: {
        ecmaVersion: 2020,
        sourceType: 'module',
    },
    rules: {
        semi: 2,
        quotes: [2, 'single', { avoidEscape: true }],
        'comma-dangle': [2, 'always-multiline'],
        'prettier/prettier': 1,
        'brace-style': [2, '1tbs', { allowSingleLine: true }],
    },
};