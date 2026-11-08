import { Brand } from '../shared/Brand';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ApiClient, ApiError, errorMessage, isCancelled, type Identity } from '../../api/client';

export function Login({ client, onLogin, expired = false }: { client: ApiClient; onLogin: (identity: Identity) => void; expired?: boolean }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const active = useRef(true);
  const usernameInput = useRef<HTMLInputElement>(null);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (pending) return;
    setPending(true); setError('');
    try {
      const identity = await client.login(username, password);
      if (active.current) onLogin(identity);
    } catch (cause) {
      if (active.current && !isCancelled(cause)) {
        usernameInput.current?.focus();
        setError(cause instanceof ApiError && cause.status === 401
        ? '관리자 이름 또는 비밀번호를 확인하세요.'
        : errorMessage(cause, '로그인하지 못했습니다. 잠시 후 다시 시도하세요.'));
      }
    } finally {
      if (active.current) { setPassword(''); setPending(false); }
    }
  }
  return <main className="login-page">
    <header className="login-wordmark"><Brand /><span className="access-label">비공개 관리 콘솔</span></header>
    <div className="login-layout">
    <section className="login-intro" aria-labelledby="purpose-title">
      <p className="eyebrow">SSH · HTTP · HTTPS</p>
      <h2 id="purpose-title">관측한 시도를,<br />검토할 수 있는 증거로.</h2>
      <p className="muted">허니팟에 남은 기록을 살펴보고, 근거를 확인한 신고를 준비하세요.</p>
      <ol className="workflow-steps">
        <li><span className="step-index">01</span><div><strong>관측</strong><p>접속과 요청을 기록합니다.</p></div></li>
        <li><span className="step-index">02</span><div><strong>검토</strong><p>IP별 증거와 신고 근거를 확인합니다.</p></div></li>
        <li><span className="step-index">03</span><div><strong>신고</strong><p>증거와 연락처를 확인하고 신고 초안을 검토합니다.</p></div></li>
      </ol>
    </section>
    <section className="login-form" aria-labelledby="login-title">
      <p className="eyebrow">관리자 접속</p>
      <h1 id="login-title">관리자 로그인</h1>
      <p className="muted">로컬에서 생성한 관리자 계정으로 접속하세요.</p>
      {expired && <p className="notice" role="status">세션이 만료되었습니다. 다시 로그인하세요.</p>}
      <form onSubmit={submit} aria-busy={pending}>
        <label>관리자 이름<input ref={usernameInput} name="username" spellCheck={false} autoCapitalize="none" autoComplete="username" required maxLength={64} value={username} onChange={(e) => setUsername(e.target.value)} aria-describedby={error ? 'login-error' : undefined} aria-invalid={!!error} /></label>
        <label>비밀번호<input name="password" type="password" autoComplete="current-password" required maxLength={1024} value={password} onChange={(e) => setPassword(e.target.value)} aria-describedby={error ? 'login-error' : undefined} aria-invalid={!!error} /></label>
        <div className="form-feedback">{error && <p className="error" id="login-error" role="alert">{error}</p>}</div>
        <button className="primary" type="submit" disabled={pending}>{pending ? '로그인 중…' : '로그인'}</button>
      </form>
    <p className="login-help">비공개 관리 화면입니다.<br />서버에서 생성한 계정을 사용하세요.</p>
    </section>
    </div>
    <footer className="login-footer"><span>Cheesetrap · 개인 운영자를 위한 허니팟 관리</span><span>관측 · 검토 · 신고</span></footer>
  </main>;
}
