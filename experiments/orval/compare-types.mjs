import { mkdir, readFile, writeFile } from "node:fs/promises";
import ts from "../../web/node_modules/typescript/lib/typescript.js";

// Compare frozen migration contracts without installing the retired generator.
// Intentional API changes require review of the baseline fixtures.
const root = new URL("../../", import.meta.url);
process.chdir(root.pathname);
const baseline = process.argv[2] ?? "f2006be6da67e2eb264ec1d904631abc4cc3e2d9";
await mkdir(".local/orval", { recursive: true });
const spec = JSON.parse(await readFile("api/openapi.json", "utf8"));
const statements = [
  'import type { components as Old, operations as OldOps } from "../../experiments/orval/baseline/schema";',
  'import type { components as New, operations as NewOps } from "../../web/src/api/schema";',
  'import type { components as OldFixture, operations as OldFixtureOps } from "../../experiments/orval/baseline/fixtures";',
  'import type * as Fixture from "./fixtures-orval";',
  'import type * as Converted from "./fixtures-converted";',
  "type Assert<T extends true> = T;",
  "type Equal<A, B> = [A] extends [B] ? [B] extends [A] ? true : false : false;",
  "type Optional<T, K extends keyof T> = {} extends Pick<T, K> ? true : false;",
];
// ADR 0003 removes sending contracts. Compare retained fields against the frozen
// baseline after those explicit removals, including nested report views.
statements.push(
  "type Draft = Omit<Old['schemas']['ReportSummary'], 'delivery_uncertain' | 'has_delivery_attempts'>;",
  "type Revision = Omit<Old['schemas']['RevisionView'], 'auto_approval_allowed'>;",
  "type GapIncident = {started_at: string; observed_through: string; causes: string[]};",
  "type Sensor = Old['schemas']['SensorStatus'] & {last_gap: GapIncident | null};",
  "type Status = Omit<Old['schemas']['Status'], 'smtp_results' | 'sensors'> & {sensors: Sensor[] | null};",
  "type Settings = Omit<Old['schemas']['Settings'], 'automatic_mode' | 'delivery_limits'>;",
);
const reviewed = {
  CollectionGapIncident: "GapIncident",
  SensorStatus: "Sensor",
  ReportDraft: "Draft",
  DetectionView: "Omit<Old['schemas']['DetectionView'], 'auto_approval_allowed'>",
  RulePageOutputBody: "Omit<Old['schemas']['RulePageOutputBody'], 'items'> & {items: Omit<Old['schemas']['RuleView'], 'auto_approval_allowed'>[] | null}",
  RuleView: "Omit<Old['schemas']['RuleView'], 'auto_approval_allowed'>",
  RevisionView: "Revision",
  Status: "Status",
  Settings: "Settings",
  SettingsOutputBody: "Omit<Old['schemas']['SettingsOutputBody'], 'automatic_mode' | 'delivery_limits' | 'smtp_test_recipient' | 'latest_smtp_test'>",
  SettingsPatchInputBody: "Omit<Old['schemas']['SettingsPatchInputBody'], 'automatic_mode' | 'delivery_limits'>",
  ReportDetailOutputBody: "Omit<Old['schemas']['ReportDetailOutputBody'], 'delivery_uncertain' | 'has_delivery_attempts' | 'revision'> & {revision: Revision}",
  ReportListOutputBody: "Omit<Old['schemas']['ReportListOutputBody'], 'items'> & {items: Draft[] | null}",
  IpOutputBody: "Omit<Old['schemas']['IpOutputBody'], 'reports' | 'detections'> & {reports: Draft[] | null, detections: Omit<Old['schemas']['DetectionView'], 'auto_approval_allowed'>[] | null}",
  OverviewOutputBody: "Omit<Old['schemas']['OverviewOutputBody'], 'operations' | 'reports_queued' | 'reports_sending' | 'reports_retry_wait' | 'reports_unknown' | 'reports_sent' | 'reports_failed' | 'reports_closed_unconfirmed'> & {operations: Status; sensors_recent_gaps: string}",
};
let index = 0;
for (const name of Object.keys(spec.components.schemas)) {
  const key = JSON.stringify(name);
  const old = reviewed[name] ?? `Old['schemas'][${key}]`;
  statements.push(`type Model${index} = Assert<Equal<${old}, New['schemas'][${key}]>>;`);
  statements.push(`type Keys${index++} = Assert<Equal<keyof (${old}), keyof New['schemas'][${key}]>>;`);
}
let queries = 0;
for (const item of Object.values(spec.paths)) {
  for (const method of ["get", "put", "post", "delete", "patch", "head", "options", "trace"]) {
    const operation = item[method];
    if (!operation?.parameters?.some((p) => p.in === "query")) continue;
    const key = JSON.stringify(operation.operationId);
    if (operation.operationId === 'reports-list') {
      statements.push("type ReportQuery = Assert<Equal<Omit<NonNullable<OldOps['reports-list']['parameters']['query']>, 'state'> & {state?: 'held' | 'needs_review' | 'rejected' | 'archived'}, NonNullable<NewOps['reports-list']['parameters']['query']>>>;");
      queries++;
      continue;
    }
    statements.push(`type Query${queries++} = Assert<Equal<NonNullable<OldOps[${key}]['parameters']['query']>, NonNullable<NewOps[${key}]['parameters']['query']>>>;`);
  }
}
for (const name of ["Probe", "One", "Any", "All"]) {
  statements.push(`type Fixture${name} = Assert<Equal<OldFixture['schemas']['${name}'], Fixture.${name}>>;`);
}
statements.push(
  "type FixtureQuery = Assert<Equal<OldFixtureOps['probe-get']['parameters']['query'], Fixture.ProbeGetParams>>;",
  "type RequiredNullable = Assert<Equal<Fixture.Probe['required_nullable'], string | null>>;",
  "type RequiredFlag = Assert<Equal<Optional<Fixture.Probe, 'required_nullable'>, false>>;",
  "type OptionalNullable = Assert<Equal<Fixture.Probe['optional_nullable'], string | null | undefined>>;",
  "type OptionalFlag = Assert<Optional<Fixture.Probe, 'optional_nullable'>>;",
  "type EnumUnion = Assert<Equal<Fixture.Probe['state'], 'ready' | 'held' | null>>;",
  "type NullableArray = Assert<Equal<Fixture.Probe['items'], string[] | null>>;",
  "type OneUnion = Assert<Equal<Fixture.One, string | number>>;",
  "type AnyUnion = Assert<Equal<Fixture.Any, string | boolean>>;",
  "type WireTimestamp = Assert<Equal<Fixture.Probe['timestamp'], string>>;",
  "type WireDate = Assert<Equal<Fixture.Probe['date_only'], string>>;",
  "type WireInt64 = Assert<Equal<Fixture.Probe['integer64'], number>>;",
  "type StringInt64 = Assert<Equal<Fixture.Probe['wire_integer64'], string>>;",
  "type DateOption = Assert<Equal<Converted.Probe['timestamp'], Date>>;",
  "type DateOnlyOption = Assert<Equal<Converted.Probe['date_only'], Date>>;",
  "type BigIntOption = Assert<Equal<Converted.Probe['integer64'], bigint>>;",
  "type StringInt64Option = Assert<Equal<Converted.Probe['wire_integer64'], string>>;",
  "// @ts-expect-error null does not satisfy a required string",
  "const wrongText: Fixture.Probe['required_text'] = null;",
  "// @ts-expect-error undefined does not satisfy required nullable",
  "const wrongNull: Fixture.Probe['required_nullable'] = undefined;",
  "// @ts-expect-error enum excludes other strings",
  "const wrongEnum: Fixture.Probe['state'] = 'other';",
  "// @ts-expect-error required query parameter must be present",
  "const wrongQuery: Fixture.ProbeGetParams = {};",
  "// @ts-expect-error closed empty request bodies reject extra properties",
  "const oldClosed: Old['schemas']['Settings-smtp-testRequest'] = { unexpected: true };",
  "// @ts-expect-error Orval must preserve the same closed empty body contract",
  "const newClosed: New['schemas']['Settings-smtp-testRequest'] = { unexpected: true };",
);
await writeFile(".local/orval/compare.ts", statements.join("\n") + "\n");
const program = ts.createProgram([".local/orval/compare.ts", "web/orval.config.ts", "web/orval.fixtures.config.ts"], {
  strict: true,
  exactOptionalPropertyTypes: true,
  noEmit: true,
  skipLibCheck: true,
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  types: [],
});
const diagnostics = ts.getPreEmitDiagnostics(program);
const failures = diagnostics.map((diagnostic) => {
  const position = diagnostic.file?.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
  return {
    file: diagnostic.file?.fileName,
    line: position ? position.line + 1 : null,
    code: diagnostic.code,
    message: ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
  };
});
const generated = ts.createSourceFile("models.ts", await readFile("web/src/api/generated/models.ts", "utf8"), ts.ScriptTarget.Latest, true);
const typeOnly = generated.statements.every((node) => ts.isTypeAliasDeclaration(node) || ts.isInterfaceDeclaration(node));
if (!typeOnly) throw new Error("Unexpected runtime declarations in generated models");
await writeFile(".local/orval/type-comparison.json", JSON.stringify({ baseline, models: index, queries, typeOnly, failures }, null, 2) + "\n");
console.log(`CHECKED: ${index} model shapes and keys, ${queries} queries, synthetic contracts, type-only output`);
if (diagnostics.length) {
  console.error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => process.cwd(),
    getCanonicalFileName: (f) => f,
    getNewLine: () => "\n",
  }));
  process.exitCode = 1;
} else {
  console.log(`PASS: ${index} models, ${queries} query contracts, synthetic unions/null/optional/date/int64, and config types`);
}
