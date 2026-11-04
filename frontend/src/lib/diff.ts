export interface DiffPart {
  type: 'same' | 'add' | 'del';
  text: string;
}

export interface SplitDiffRow {
  lineNumLeft?: number;
  lineNumRight?: number;
  leftContent?: string;
  rightContent?: string;
  type: 'same' | 'modified' | 'added' | 'deleted';
  leftTokens?: DiffPart[];
  rightTokens?: DiffPart[];
}

const MAX_DIFF_TOKENS = 2000;
const MAX_DIFF_LINES = 2000;

/** Word-level LCS diff (whitespace preserved). Inputs are short CLI snippets. */
export function diffWords(a: string, b: string): DiffPart[] {
  const x = a.split(/(\s+)/).filter(Boolean);
  const y = b.split(/(\s+)/).filter(Boolean);

  // Untrusted model output can be arbitrarily long: refuse to allocate an
  // O(n*m) matrix beyond a bounded size and fall back to a full replacement.
  if (x.length > MAX_DIFF_TOKENS || y.length > MAX_DIFF_TOKENS) {
    const fallback: DiffPart[] = [
      { type: 'del', text: a },
      { type: 'add', text: b },
    ];
    return fallback.filter((part) => part.text.length > 0);
  }

  const dp: number[][] = Array.from({ length: x.length + 1 }, () =>
    new Array<number>(y.length + 1).fill(0)
  );
  for (let i = x.length - 1; i >= 0; i--) {
    const row = dp[i];
    const nextRow = dp[i + 1];
    if (!row || !nextRow) continue;
    for (let j = y.length - 1; j >= 0; j--) {
      row[j] =
        x[i] === y[j]
          ? (nextRow[j + 1] ?? 0) + 1
          : Math.max(nextRow[j] ?? 0, row[j + 1] ?? 0);
    }
  }

  const out: DiffPart[] = [];
  const push = (type: DiffPart['type'], text: string) => {
    const last = out[out.length - 1];
    if (last && last.type === type) last.text += text;
    else out.push({ type, text });
  };
  let i = 0;
  let j = 0;
  while (i < x.length && j < y.length) {
    const currentX = x[i] ?? '';
    const currentY = y[j] ?? '';
    if (currentX === currentY) {
      push('same', currentX);
      i++;
      j++;
    } else if ((dp[i + 1]?.[j] ?? 0) >= (dp[i]?.[j + 1] ?? 0)) {
      push('del', currentX);
      i++;
    } else {
      push('add', currentY);
      j++;
    }
  }
  while (i < x.length) push('del', x[i++] ?? '');
  while (j < y.length) push('add', y[j++] ?? '');
  return out;
}

/** Compute line-by-line side-by-side git diff with synchronized token-level highlighting. */
export function computeSplitDiff(original: string, sanitized: string): SplitDiffRow[] {
  const leftLines = original.split('\n');
  const rightLines = sanitized.split('\n');

  // Bound both the line matrix and each line's word diff.
  if (leftLines.length > MAX_DIFF_LINES || rightLines.length > MAX_DIFF_LINES) {
    return [
      ...leftLines.map((line, idx) => ({
        lineNumLeft: idx + 1,
        leftContent: line,
        type: 'deleted' as const,
      })),
      ...rightLines.map((line, idx) => ({
        lineNumRight: idx + 1,
        rightContent: line,
        type: 'added' as const,
      })),
    ];
  }

  // If equal line count, direct paired alignment with word-level diff
  if (leftLines.length === rightLines.length) {
    return leftLines.map((left, idx) => {
      const right = rightLines[idx] ?? '';
      const lineNum = idx + 1;
      if (left === right) {
        return {
          lineNumLeft: lineNum,
          lineNumRight: lineNum,
          leftContent: left,
          rightContent: right,
          type: 'same',
        };
      }
      const words = diffWords(left, right);
      return {
        lineNumLeft: lineNum,
        lineNumRight: lineNum,
        leftContent: left,
        rightContent: right,
        type: 'modified',
        leftTokens: words.filter((w) => w.type === 'same' || w.type === 'del'),
        rightTokens: words.filter((w) => w.type === 'same' || w.type === 'add'),
      };
    });
  }

  // Line-level LCS alignment
  const dp: number[][] = Array.from({ length: leftLines.length + 1 }, () =>
    new Array<number>(rightLines.length + 1).fill(0)
  );

  for (let i = leftLines.length - 1; i >= 0; i--) {
    const row = dp[i];
    const nextRow = dp[i + 1];
    if (!row || !nextRow) continue;
    for (let j = rightLines.length - 1; j >= 0; j--) {
      row[j] =
        leftLines[i] === rightLines[j]
          ? (nextRow[j + 1] ?? 0) + 1
          : Math.max(nextRow[j] ?? 0, row[j + 1] ?? 0);
    }
  }

  const rows: SplitDiffRow[] = [];
  let i = 0;
  let j = 0;
  let leftNum = 1;
  let rightNum = 1;

  while (i < leftLines.length && j < rightLines.length) {
    const left = leftLines[i] ?? '';
    const right = rightLines[j] ?? '';
    if (left === right) {
      rows.push({
        lineNumLeft: leftNum++,
        lineNumRight: rightNum++,
        leftContent: left,
        rightContent: right,
        type: 'same',
      });
      i++;
      j++;
    } else if ((dp[i + 1]?.[j] ?? 0) >= (dp[i]?.[j + 1] ?? 0)) {
      // Check if paired with next right line for inline modification
      if ((dp[i]?.[j + 1] ?? 0) === (dp[i + 1]?.[j] ?? 0)) {
        const words = diffWords(left, right);
        rows.push({
          lineNumLeft: leftNum++,
          lineNumRight: rightNum++,
          leftContent: left,
          rightContent: right,
          type: 'modified',
          leftTokens: words.filter((w) => w.type === 'same' || w.type === 'del'),
          rightTokens: words.filter((w) => w.type === 'same' || w.type === 'add'),
        });
        i++;
        j++;
      } else {
        rows.push({
          lineNumLeft: leftNum++,
          leftContent: left,
          type: 'deleted',
        });
        i++;
      }
    } else {
      rows.push({
        lineNumRight: rightNum++,
        rightContent: right,
        type: 'added',
      });
      j++;
    }
  }

  while (i < leftLines.length) {
    rows.push({
      lineNumLeft: leftNum++,
      leftContent: leftLines[i++] ?? '',
      type: 'deleted',
    });
  }

  while (j < rightLines.length) {
    rows.push({
      lineNumRight: rightNum++,
      rightContent: rightLines[j++] ?? '',
      type: 'added',
    });
  }

  return rows;
}
