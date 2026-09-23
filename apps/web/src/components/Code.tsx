import hljs from "highlight.js/lib/core";
import java from "highlight.js/lib/languages/java";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import php from "highlight.js/lib/languages/php";
import python from "highlight.js/lib/languages/python";
import typescript from "highlight.js/lib/languages/typescript";
import xml from "highlight.js/lib/languages/xml";
import { useMemo } from "react";

hljs.registerLanguage("python", python);
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("typescript", typescript);
hljs.registerLanguage("php", php);
hljs.registerLanguage("java", java);
hljs.registerLanguage("json", json);
hljs.registerLanguage("xml", xml);

/** Langage de coloration d'après le nom de fichier (les manifests ne sont pas du code source). */
export function highlightLanguage(file: string, language: string): string | null {
  if (file.endsWith(".json")) return "json";
  if (file.endsWith(".xml")) return "xml";
  if (file.endsWith(".txt") || file.endsWith(".toml") || file.endsWith(".lock")) return null;
  return hljs.getLanguage(language) ? language : null;
}

function highlightLine(line: string, language: string | null): string {
  if (!language) return escapeHtml(line);
  // PHP : les fragments sans balise ouvrante sont colorés en mode PHP pur
  const lang = language === "php" ? "php" : language;
  return hljs.highlight(line || " ", { language: lang, ignoreIllegals: true }).value;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

interface CodeViewProps {
  file: string;
  language: string;
  code: string;
  startLine: number;
  highlightFrom: number;
  highlightTo: number;
}

export function CodeView({ file, language, code, startLine, highlightFrom, highlightTo }: CodeViewProps) {
  const lang = highlightLanguage(file, language);
  const lines = useMemo(() => code.split("\n").map((l) => highlightLine(l, lang)), [code, lang]);
  return (
    <div className="code-view">
      <div className="file mono">{file}</div>
      <table>
        <tbody>
          {lines.map((html, i) => {
            const n = startLine + i;
            const hl = n >= highlightFrom && n <= highlightTo;
            return (
              <tr key={n} className={hl ? "hl" : undefined}>
                <td className="ln mono">{n}</td>
                {/* secuscan: ignore[JS-XSS] HTML produit par highlight.js ou escapeHtml, qui échappent le code */}
                <td className="mono" dangerouslySetInnerHTML={{ __html: html }} />
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function DiffView({ diff, file, language }: { diff: string; file: string; language: string }) {
  const lang = highlightLanguage(file, language);
  const rows = diff.split("\n").filter((l) => !l.startsWith("---") && !l.startsWith("+++"));
  let oldLine = 0;
  let newLine = 0;
  return (
    <div className="code-view diff-view">
      <div className="file mono">{file}</div>
      <table>
        <tbody>
          {rows.map((raw, i) => {
            const hunk = raw.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)/);
            if (hunk) {
              oldLine = Number(hunk[1]);
              newLine = Number(hunk[2]);
              return (
                <tr key={i} className="hunk">
                  <td className="ln mono" />
                  <td className="sign mono" />
                  <td className="mono">{raw}</td>
                </tr>
              );
            }
            const sign = raw[0] ?? " ";
            const text = raw.slice(1);
            const cls = sign === "+" ? "add" : sign === "-" ? "del" : undefined;
            const num = sign === "+" ? newLine++ : sign === "-" ? oldLine++ : (oldLine++, newLine++);
            return (
              <tr key={i} className={cls}>
                <td className="ln mono">{num}</td>
                <td className="sign mono">{sign === " " ? "" : sign}</td>
                {/* secuscan: ignore[JS-XSS] HTML produit par highlight.js ou escapeHtml, qui échappent le code */}
                <td className="mono" dangerouslySetInnerHTML={{ __html: highlightLine(text, lang) }} />
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
