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
          <span style={{ fontSize: 13, color: 'var(--text-main)', fontWeight: 500 }}>
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
              background: isHovered ? 'rgba(98, 114, 240, 0.2)' : 'rgba(98, 114, 240, 0.1)',
              border: '1px solid rgba(98, 114, 240, 0.3)',
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
            <div
              style={{
                position: 'absolute',
                bottom: 'calc(100% + 10px)',
                right: 0,
                width: 340,
                maxWidth: '90vw',
                padding: '12px 14px',
                background: 'var(--surface-elevated, #1c1c21)',
                border: '1px solid var(--border-focus, rgba(98, 114, 240, 0.45))',
                borderRadius: 'var(--radius, 8px)',
                boxShadow: '0 12px 28px -4px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(98, 114, 240, 0.2)',
                fontSize: 12.5,
                lineHeight: 1.55,
                color: 'var(--text-main, #e4e4e7)',
                zIndex: 1000,
                pointerEvents: 'none',
                textAlign: 'left',
              }}
            >
              <div
                style={{
                  fontWeight: 600,
                  color: 'var(--accent, #6272f0)',
                  marginBottom: 6,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: 13,
                }}
              >
                <ShieldIcon width={14} height={14} /> How Your Keys Are Protected
              </div>
              <div style={{ color: 'var(--text-subtle)' }}>{explanation}</div>
              {/* Tooltip Downward Arrow */}
              <div
                style={{
                  position: 'absolute',
                  top: '100%',
                  right: 28,
                  width: 0,
                  height: 0,
                  borderLeft: '6px solid transparent',
                  borderRight: '6px solid transparent',
                  borderTop: '6px solid var(--border-focus, rgba(98, 114, 240, 0.45))',
                }}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
