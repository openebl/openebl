module.exports = {
  printWidth: 120,
  tabWidth: 2,
  useTabs: false,
  singleQuote: true,
  semi: false,
  trailingComma: 'all',
  bracketSpacing: true,
  svelteBracketNewLine: false,
  importOrder: [
    "^@/(.*)$",
    "^@(.*)/(.*)$",
    "^[./]",
  ],
  importOrderSeparation: true,
  importOrderSortSpecifiers: true,
  importOrderParserPlugins: [
    "typescript",
    "classProperties",
    "decorators-legacy",
  ]
}
