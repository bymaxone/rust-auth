module.exports = {
  extends: ['@commitlint/config-conventional'],
  plugins: [require('./scripts/commitlint-no-ai-attribution.cjs')],
  rules: { 'no-ai-attribution': [2, 'always'] },
};
