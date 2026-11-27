import { useState, type FormEvent } from 'react';
import { api } from '../../api/client';
import { AlertIcon, ShieldIcon } from '../../components/ApertureIcons';
import { CodeBlock } from '../../components/Primitives';
import type { GuardrailTestResponse } from '../../types/api';

export const PLAYGROUND_PRESETS = [
  {
    label: 'Secret + Email PII',
    text: 'Deploy with OPENAI_API_KEY=sk-proj-9f8e7d6c5b4a32109876543210abcdef and notify ops-lead@acme.internal.',
  },
  {
    label: 'AWS Access Key',
    text: 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\nssn = 123-45-6789',
  },
  {
    label: 'Clean Prompt',
    text: 'Summarize Kubernetes pod restart causes in three concise bullet points.',
  },
];

export function GuardrailPlayground() {
  const [sampleText, setSampleText] = useState(PLAYGROUND_PRESETS[0].text);
  const [testResult, setTestResult] = useState<GuardrailTestResponse | null>(null);
  const [testingGuardrail, setTestingGuardrail] = useState(false);
  const [playgroundError, setPlaygroundError] = useState<string | null>(null);

  const runPlayground = async (textToTest: string) => {
    setTestingGuardrail(true);
    setPlaygroundError(null);
    try {
      const res = await api.testGuardrails(textToTest);
      setTestResult(res);
    } catch (err: unknown) {
      setPlaygroundError(
        err instanceof Error ? err.message : 'Guardrail evaluation failed',
      );
    } finally {
      setTestingGuardrail(false);
    }
  };

  const handleRunTest = (event: FormEvent) => {
    event.preventDefault();
    void runPlayground(sampleText);
  };

  const verdictAction = (testResult?.action || 'allow').toLowerCase();

  return (
    <section className="ap-bezel-tray" aria-label="Live Guardrail Playground">
      <div className="ap-card">
        <div className="ap-card-header">
          <div>
            <h2 className="ap-card-title">Live Guardrail Playground</h2>
            <p className="ap-card-subtitle">
              Paste a sample prompt or JSON body to simulate active detectors and preview `[REDACTED:...]` output.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {PLAYGROUND_PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                className="ap-btn ap-btn-sm"
                onClick={() => {
                  setSampleText(preset.text);
                  void runPlayground(preset.text);
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={handleRunTest} className="ap-card-body ap-split-2">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <textarea
              className="ap-textarea ap-mono"
              style={{ minHeight: 118 }}
              value={sampleText}
              onChange={(e) => setSampleText(e.target.value)}
              placeholder="Paste sample prompt or JSON request..."
              aria-label="Sample prompt to evaluate against guardrails"
            />
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
              <span className="ap-hint">
                Evaluates against all currently enabled rules in SQLite & YAML.
              </span>
              <button
                type="submit"
                className="ap-btn ap-btn-primary"
                disabled={testingGuardrail || !sampleText.trim()}
              >
                <ShieldIcon size={15} />
                <span>{testingGuardrail ? 'Evaluating...' : 'Evaluate Sample'}</span>
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }}>
            {playgroundError && (
              <div className="ap-alert ap-alert--danger">
                <AlertIcon style={{ flexShrink: 0, marginTop: 1 }} />
                <span>{playgroundError}</span>
              </div>
            )}

            {testResult ? (
              <>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    flexWrap: 'wrap',
                  }}
                >
                  <span
                    className={`ap-badge ${
                      verdictAction === 'block'
                        ? 'ap-badge--red'
                        : verdictAction === 'redact'
                          ? 'ap-badge--amber'
                          : 'ap-badge--green'
                    }`}
                  >
                    Verdict: {verdictAction.toUpperCase()}
                  </span>
                  {(testResult.matches ?? []).length > 0 ? (
                    (testResult.matches ?? []).map((m) => (
                      <span key={m.rule_id} className="ap-badge ap-mono">
                        {m.rule_name} ({m.action})
                      </span>
                    ))
                  ) : (
                    <span style={{ color: 'var(--ap-text-secondary)', fontSize: 12 }}>
                      No rules matched — request allowed unchanged.
                    </span>
                  )}
                </div>
                <CodeBlock
                  label="Evaluated / Redacted Output"
                  code={testResult.redacted_text}
                  highlightRedactions
                />
              </>
            ) : (
              <div
                style={{
                  flex: 1,
                  minHeight: 118,
                  borderRadius: 'var(--ap-radius-md)',
                  border: '1px dashed var(--ap-border-strong)',
                  background: 'var(--ap-subcard-bg)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: 16,
                  color: 'var(--ap-text-secondary)',
                  fontSize: 12.5,
                  textAlign: 'center',
                }}
              >
                Click &ldquo;Evaluate Sample&rdquo; or pick a preset above to inspect rule hits and redactions.
              </div>
            )}
          </div>
        </form>
      </div>
    </section>
  );
}
