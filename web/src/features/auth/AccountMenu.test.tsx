import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { AccountMenu } from './AccountMenu';

it('keeps logout inside the account disclosure and closes with Escape or outside interaction', () => {
 const logout = vi.fn();
 render(<><AccountMenu username="operator" loggingOut={false} onLogout={logout} /><button>다른 작업</button></>);
 const trigger = screen.getByRole('button', {name: '계정 메뉴: operator'});
 expect(screen.queryByRole('button', {name: '로그아웃'})).not.toBeInTheDocument();
 fireEvent.click(trigger);
 const action = screen.getByRole('button', {name: '로그아웃'});
 action.focus(); fireEvent.keyDown(action, {key: 'Escape'});
 expect(trigger).toHaveFocus(); expect(trigger).toHaveAttribute('aria-expanded', 'false');
 fireEvent.click(trigger); fireEvent.pointerDown(screen.getByRole('button', {name: '다른 작업'}));
 expect(trigger).toHaveAttribute('aria-expanded', 'false');
 fireEvent.click(trigger); fireEvent.click(screen.getByRole('button', {name: '로그아웃'}));
 expect(logout).toHaveBeenCalledOnce(); expect(trigger).toHaveFocus();
});
