module.exports = {
    "env": {
        "es2021": true,
        "node": true
    },
    "extends": [
        "eslint:recommended",
        "plugin:@typescript-eslint/recommended",
        "prettier"
    ],
    "parser": "@typescript-eslint/parser",
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module",
        "project": [ "./tsconfig.json" ]
    },
    "plugins": [
        "@typescript-eslint"
    ],
    "rules": {
        "eqeqeq": ["error", "always"]
    },
    "ignorePatterns": [ "**/.eslintrc.js", "**/jest.config.js", "**/*.test.ts" ]
}
