import { useEffect, useId, useRef, useState } from 'react';

export function AccountMenu({ username, loggingOut, onLogout }: {
 username: string; loggingOut: boolean; onLogout: () => void;
}) {
 const [open, setOpen] = useState(false);
 const root = useRef<HTMLDivElement>(null);
 const trigger = useRef<HTMLButtonElement>(null);
 const panelId = useId();
 useEffect(() => {
  if (!open) return;
  const dismiss = (event: PointerEvent) => {
   if (!root.current?.contains(event.target as Node)) setOpen(false);
  };
  document.addEventListener('pointerdown', dismiss);
  return () => document.removeEventListener('pointerdown', dismiss);
 }, [open]);
 return <div className="account-menu" ref={root}
  onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false); }}
  onKeyDown={event => {
   if (event.key === 'Escape' && open) {
    event.preventDefault(); setOpen(false); trigger.current?.focus();
   }
  }}>
  <button ref={trigger} className="account-trigger" aria-label={`계정 메뉴: ${username}`}
   aria-expanded={open} aria-controls={panelId} disabled={loggingOut}
   onClick={() => setOpen(value => !value)}>
   <span className="username">{loggingOut ? '로그아웃 중…' : username}</span>
   <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="m3 4.5 3 3 3-3" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg>
  </button>
  {open && <div id={panelId} className="account-panel" role="group" aria-label="계정">
   <p className="muted">로그인 계정</p><strong>{username}</strong>
   <button onClick={() => { setOpen(false); trigger.current?.focus(); onLogout(); }} disabled={loggingOut}>로그아웃</button>
  </div>}
 </div>;
}
