import { useState } from "react";
import { ApiClient } from "../../api/client";
import { CollectionStatus } from "../status/CollectionStatus";
export function Overview({ client }: { client: ApiClient }) {
  const [refreshRevision, setRefreshRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  return (
    <section className="overview-page">
      <div className="section-heading">
        <div><h1>개요</h1>
          <p className="muted">신고를 검토하고 수집 상태를 확인하세요.</p>
        </div>
        <button className="quiet" aria-label="개요 새로고침" disabled={loading} onClick={() => setRefreshRevision(n => n + 1)}>새로고침</button>
      </div>
      <CollectionStatus client={client} dashboard refreshRevision={refreshRevision} onLoadingChange={setLoading} />
      <section className="overview-workflow" aria-labelledby="workflow-title">
        <div><h2 id="workflow-title">작업 이어가기</h2><p className="muted">관측 기록과 신고 근거를 구분해 검토합니다.</p></div>
        <div className="workflow-links">
          <a href="/events"><span className="step-index">01</span><span><strong>이벤트 탐색</strong><small>서비스·기간·판정 결과로 기록 확인</small></span><span aria-hidden="true">↗</span></a>
          <a href="/reports?state=held"><span className="step-index">02</span><span><strong>보류 신고 검토</strong><small>연락처와 증거의 보류 사유 확인</small></span><span aria-hidden="true">↗</span></a>
        </div>
      </section>
    </section>
  );
}
