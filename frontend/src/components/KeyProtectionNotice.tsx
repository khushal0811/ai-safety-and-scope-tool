import { useState } from 'react';
import { ShieldIcon } from './Icons';

interface Props {
  compact?: boolean;
}

export function KeyProtectionNotice({ compact = false }: Props) {
  const [isHovered, setIsHovered] = useState(false);

  const explanation =
    'We use military-grade AES-256-GCM encryption on our server before your key ever touches our database. Because your key is encrypted using an isolated server-side master key, anyone looking at our database only sees a random, useless string of text.';

  return (
    <div
      style={{
        position: 'relative',
        display: 'block',
        width: '100%',
      }}
    >
      <div
        className="note"
        style={{
          margin: 0,
          padding: compact ? '10px 14px' : '12px 16px',
          background: 'rgba(98, 114, 240, 0.06)',
          border: '1px solid rgba(98, 114, 240, 0.22)',
          borderRadius: 'var(--radius)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          flexWrap: 'wrap',
        }}
      >
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          <ShieldIcon width={16} height={16} style={{ color: 'var(--accent)', flexShrink: 0 }} />
          <span style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>
            Your API keys are private &amp; safe
          </span>
        </div>

        {/* Hover trigger element */}
        <div
          style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={() => setIsHovered(false)}
          onClick={() => setIsHovered((prev) => !prev)}
          tabIndex={0}
          role="button"
          aria-label="How Your Keys Are Protected"
        >
          <span
            style={{
              fontSize: 12.5,
              color: 'var(--accent)',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 10px',
              borderRadius: 6,
              background: isHovered ? 'var(--accent-glow)' : 'transparent',
              border: '1px solid var(--border-s)',
              transition: 'all 0.15s ease',
              userSelect: 'none',
              fontWeight: 500,
            }}
          >
            <span>How Your Keys Are Protected</span>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 17,
                height: 17,
                borderRadius: '50%',
                background: 'var(--accent)',
                color: '#fff',
                fontSize: 11,
                fontWeight: 700,
                lineHeight: 1,
              }}
            >
              ?
            </span>
          </span>

          {/* Floating Tooltip on hover/click */}
          {isHovered && (
            <div className="key-protection-popover">
              <div className="key-protection-popover__title">
                <ShieldIcon width={14} height={14} />
                <span>How Your Keys Are Protected</span>
              </div>
              <div className="key-protection-popover__body">{explanation}</div>
              {/* Tooltip Downward Arrow with Border */}
              <div className="key-protection-popover__arrow" />
              <div className="key-protection-popover__arrow-inner" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
