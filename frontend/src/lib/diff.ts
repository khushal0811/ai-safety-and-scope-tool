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

/** Word-level LCS diff (whitespace preserved). Inputs are short CLI snippets. */
export function diffWords(a: string, b: string): DiffPart[] {
  const x = a.split(/(\s+)/).filter(Boolean);
  const y = b.split(/(\s+)/).filter(Boolean);
  const dp: number[][] = Array.from({ length: x.length + 1 }, () => new Array(y.length + 1).fill(0));
  for (let i = x.length - 1; i >= 0; i--) {
    for (let j = y.length - 1; j >= 0; j--) {
      dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
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
    if (x[i] === y[j]) {
      push('same', x[i]);
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) push('del', x[i++]);
    else push('add', y[j++]);
  }
  while (i < x.length) push('del', x[i++]);
  while (j < y.length) push('add', y[j++]);
  return out;
}

/** Compute line-by-line side-by-side git diff with synchronized token-level highlighting. */
export function computeSplitDiff(original: string, sanitized: string): SplitDiffRow[] {
  const leftLines = original.split('\n');
  const rightLines = sanitized.split('\n');

  // If equal line count, direct paired alignment with word-level diff
  if (leftLines.length === rightLines.length) {
    return leftLines.map((left, idx) => {
      const right = rightLines[idx];
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
    new Array(rightLines.length + 1).fill(0)
  );

  for (let i = leftLines.length - 1; i >= 0; i--) {
    for (let j = rightLines.length - 1; j >= 0; j--) {
      dp[i][j] =
        leftLines[i] === rightLines[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const rows: SplitDiffRow[] = [];
  let i = 0;
  let j = 0;
  let leftNum = 1;
  let rightNum = 1;

  while (i < leftLines.length && j < rightLines.length) {
    if (leftLines[i] === rightLines[j]) {
      rows.push({
        lineNumLeft: leftNum++,
        lineNumRight: rightNum++,
        leftContent: leftLines[i],
        rightContent: rightLines[j],
        type: 'same',
      });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      // Check if paired with next right line for inline modification
      if (dp[i][j + 1] === dp[i + 1][j]) {
        const words = diffWords(leftLines[i], rightLines[j]);
        rows.push({
          lineNumLeft: leftNum++,
          lineNumRight: rightNum++,
          leftContent: leftLines[i],
          rightContent: rightLines[j],
          type: 'modified',
          leftTokens: words.filter((w) => w.type === 'same' || w.type === 'del'),
          rightTokens: words.filter((w) => w.type === 'same' || w.type === 'add'),
        });
        i++;
        j++;
      } else {
        rows.push({
          lineNumLeft: leftNum++,
          leftContent: leftLines[i],
          type: 'deleted',
        });
        i++;
      }
    } else {
      rows.push({
        lineNumRight: rightNum++,
        rightContent: rightLines[j],
        type: 'added',
      });
      j++;
    }
  }

  while (i < leftLines.length) {
    rows.push({
      lineNumLeft: leftNum++,
      leftContent: leftLines[i++],
      type: 'deleted',
    });
  }

  while (j < rightLines.length) {
    rows.push({
      lineNumRight: rightNum++,
      rightContent: rightLines[j++],
      type: 'added',
    });
  }

  return rows;
}

