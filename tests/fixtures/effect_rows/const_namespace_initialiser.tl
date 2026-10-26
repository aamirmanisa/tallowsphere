// G01 P0.3 (audit N-2, second form): `const N = net` put the runtime module
// tag in a value. Walking the initialiser is what catches it — as E0146 (a
// module namespace is not a value), before any effect question arises.
const N: string = net
