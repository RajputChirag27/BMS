import tseslint from "typescript-eslint";

export default {
  rules: {
    // other rules...
    "semi": ["error", "always"],
    "indent": ["error", 2],
    "quotes": ["error", "single"],
    "no-unused-vars": "warn",
    "prefer-arrow-callback": "error",
    "arrow-parens": ["error", "always"],
    "import/extensions": ["error", "always"],
    "import/order": ["error", {"newlines-between": "always"}]
  },
  languageOptions: {
    globals: {  // Define your global variables here
      browser: false,  // Example global variable
    }
  },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended"
  ]
};
