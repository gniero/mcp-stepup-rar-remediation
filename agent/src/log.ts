const c = (code: number) => (s: string) => (process.stdout.isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = c(90), yellow = c(33), cyan = c(36), magenta = c(35), green = c(32);

export const log = {
  http: (s: string) => console.log(dim(`   [http] ${s}`)),
  oauth: (s: string) => console.log(yellow(`[oauth] ${s}`)),
  prompt: (s: string) => console.log(magenta(s)),
  tool: (s: string) => console.log(cyan(`[tool] ${s}`)),
  elicit: (s: string) => console.log(green(`[elicitation] ${s}`)),
};
