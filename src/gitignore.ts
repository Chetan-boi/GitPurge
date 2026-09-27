import ignore from "ignore";
import path from "node:path";

export function createGitIgnoreMatcher(patterns: string): (relativePath: string) => boolean {
  const matcher = ignore().add(patterns);

  return (relativePath) => {
    if (
      !relativePath
      || path.isAbsolute(relativePath)
      || relativePath === ".."
      || relativePath.startsWith(`..${path.sep}`)
    ) {
      return false;
    }

    return matcher.ignores(relativePath.split(path.sep).join("/"));
  };
}