export function Brand() {
  return <div className="brand">
    <svg className="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <path d="M6 10 17 4l10 6v13l-11 6L6 23V10Z" stroke="currentColor" strokeWidth="1.8" />
      <path d="m6 10 10 6 11-6M16 16v13" stroke="currentColor" strokeWidth="1.8" />
      <circle cx="12" cy="19" r="1.5" fill="currentColor" />
      <circle cx="21" cy="19" r="1.5" fill="currentColor" />
    </svg>
    <span><span translate="no">cheesetrap</span><span className="brand-caption">관측과 증거 검토</span></span>
  </div>;
}
