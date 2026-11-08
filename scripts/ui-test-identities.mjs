// Parse source only; never import or execute test files.
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
const require = createRequire(new URL('../web/package.json', import.meta.url));
const ts = require('typescript');

export function declarations(sources) {
  const output = {};
  for (const [path, text] of Object.entries(sources)) {
    const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true);
    if (source.parseDiagnostics.length) continue;
    const names = new Set();
    for (const node of source.statements) {
      if (!ts.isImportDeclaration(node) || node.moduleSpecifier.text !== 'vitest') continue;
      const bindings = node.importClause?.namedBindings;
      if (!bindings || !ts.isNamedImports(bindings)) continue;
      for (const binding of bindings.elements) {
        if (['it', 'test'].includes((binding.propertyName ?? binding.name).text)) names.add(binding.name.text);
      }
    }
    const found = [];
    function visit(node) {
      if (ts.isCallExpression(node) && node.arguments.length && ts.isStringLiteral(node.arguments[0])) {
        let target = node.expression;
        if (ts.isPropertyAccessExpression(target) && ['skip', 'only', 'todo'].includes(target.name.text)) target = target.expression;
        if (ts.isIdentifier(target) && names.has(target.text)) {
          // Vitest's call-site collector locates .skip/.only/.todo at the
          // property name; a plain call is located at the imported identifier.
          const callSite = ts.isPropertyAccessExpression(node.expression) ? node.expression.name : node.expression;
          const { line, character } = source.getLineAndCharacterOfPosition(callSite.getStart(source));
          found.push({ title: node.arguments[0].text, line: line + 1, column: character + 1 });
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
    output[path] = found;
  }
  return output;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.stdout.write(JSON.stringify(declarations(JSON.parse(readFileSync(0, 'utf8')))));
}
