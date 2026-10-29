// `pub(crate)` reaches the package rooted at the entry file's directory
// (here .../pubcrate_out_of_package/src). This file sits beside that root, so
// it is outside the package.
pub(crate) fn normalise(path: String) -> String {
    path
}
