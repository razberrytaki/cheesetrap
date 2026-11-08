"""Conservative backup workspace admission; no deletion to make room."""
def check_budget(local_bytes,remote_bytes,database_bytes,free_bytes,max_local,max_remote):
    values=(local_bytes,remote_bytes,database_bytes,free_bytes,max_local,max_remote)
    if any(type(v) is not int or v<0 for v in values) or database_bytes==0:
        raise ValueError('invalid_backup_budget')
    reserve=3*database_bytes
    if free_bytes<10*1024**3+reserve:raise ValueError('backup_workspace_insufficient')
    if local_bytes+reserve>max_local:raise ValueError('local_backup_budget_exceeded')
    if remote_bytes>=max_remote:raise ValueError('remote_backup_budget_exceeded')
