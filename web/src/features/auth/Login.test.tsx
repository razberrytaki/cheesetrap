import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ApiClient } from '../../api/client';
import { fetcher, identity, json } from '../../test/fixtures';
import { Login } from './Login';

function submit() {
  fireEvent.change(screen.getByLabelText('관리자 이름'), { target: { value: 'operator' } });
  fireEvent.change(screen.getByLabelText('비밀번호'), { target: { value: 'secret' } });
  fireEvent.click(screen.getByRole('button', { name: '로그인' }));
}
describe('Login', () => {
  it('distinguishes invalid credentials from connectivity errors and clears the password', async () => {
    const onLogin = vi.fn();
    const network = fetcher((url) => url.pathname.endsWith('/csrf') ? json({ csrf_token: 'fresh' }) : json({}, 401));
    render(<Login client={new ApiClient(network)} onLogin={onLogin} />);
    submit();
    expect(await screen.findByRole('alert')).toHaveTextContent('관리자 이름 또는 비밀번호를 확인하세요.');
    expect(screen.getByLabelText('비밀번호')).toHaveValue('');
    expect(onLogin).not.toHaveBeenCalled();
  });
  it('shows a connection failure without claiming the password was wrong', async () => {
    render(<Login client={new ApiClient(fetcher(() => { throw new TypeError('network'); }))} onLogin={vi.fn()} />);
    submit();
    expect(await screen.findByRole('alert')).toHaveTextContent('서버에 연결할 수 없습니다. 연결을 확인하고 다시 시도하세요.');
    expect(screen.queryByText('관리자 이름 또는 비밀번호를 확인하세요.')).not.toBeInTheDocument();
  });
  it('submits using a fresh CSRF token and returns the authenticated identity', async () => {
    const onLogin = vi.fn();
    const network = fetcher((url) => url.pathname.endsWith('/csrf') ? json({ csrf_token: 'fresh' }) : json({ admin: identity, csrf_token: 'rotated' }));
    render(<Login client={new ApiClient(network)} onLogin={onLogin} />);
    submit();
    await screen.findByRole('button', { name: '로그인' });
    await vi.waitFor(() => expect(onLogin).toHaveBeenCalledWith(identity));
    expect(network.mock.calls[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'fresh' } });
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
