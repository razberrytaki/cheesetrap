import { render, screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { ApiClient } from '../../api/client';
import { fetcher, json, overview } from '../../test/fixtures';
import { Overview } from './Overview';

it.each(['0', '9007199254740993'])('shows the reported review count without inventing or rounding it: %s', async (count) => {
  const data = { ...overview, operations: { ...overview.operations!, report_states: { needs_review: count } } };
  render(<Overview client={new ApiClient(fetcher(() => json(data)))} />);
  const panel = await screen.findByRole('region', { name: '검토 대기 신고' });
  expect(within(panel).getByRole('definition')).toHaveTextContent(count);
  expect(within(panel).getByRole('link')).toHaveAttribute('href', '/reports?state=needs_review');
});

it.each([{}, { held: '4' }])('shows zero when a successful breakdown omits needs_review: %j', async (reportStates) => {
  const data = { ...overview, operations: { ...overview.operations!, report_states: reportStates } };
  render(<Overview client={new ApiClient(fetcher(() => json(data)))} />);
  const panel = await screen.findByRole('region', { name: '검토 대기 신고' });
  expect(within(panel).getByRole('definition')).toHaveTextContent(/^0$/);
  expect(within(panel).getByText('검토 대기 신고가 없습니다.')).toBeVisible();
  expect(within(panel).getByRole('link', { name: '검토 대기 목록 확인' })).toHaveAttribute('href', '/reports?state=needs_review');
});

it.each([
  { ...overview, operations: undefined },
  { ...overview, operations: null },
  { ...overview, operations: { ...overview.operations!, report_states: undefined } },
  { ...overview, operations: { ...overview.operations!, report_states: null } },
])('keeps an unavailable report breakdown distinct from zero %#', async (data) => {
  render(<Overview client={new ApiClient(fetcher(() => json(data)))} />);
  const panel = await screen.findByRole('region', { name: '검토 대기 신고' });
  expect(within(panel).getByRole('definition')).toHaveTextContent('확인 불가');
  expect(within(panel).getByText('검토 대기 수를 확인할 수 없습니다.')).toBeVisible();
  expect(within(panel).queryByText('검토 대기 신고가 없습니다.')).not.toBeInTheDocument();
});

it('keeps a failed status read distinct from an empty dashboard', async () => {
  render(<Overview client={new ApiClient(fetcher(() => json({}, 503)))} />);
  expect(await screen.findByRole('alert')).toBeVisible();
  expect(screen.queryByText('활성 센서')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: '개요 새로고침' })).toBeEnabled();
});

it('offers only draft review and collection navigation', async () => {
 render(<Overview client={new ApiClient(fetcher(() => json(overview)))} />);
 await screen.findByRole('region', { name: '검토 대기 신고' });
 expect(screen.queryByRole('link', { name: /발송/ })).not.toBeInTheDocument();
});
