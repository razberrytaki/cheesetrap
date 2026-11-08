import unittest
from backup_budget import check_budget
GIB=1024**3
class BackupBudgetTest(unittest.TestCase):
    def test_small_snapshot_fits_without_deleting_previous_backups(self):
        check_budget(100,100,10*1024**2,20*GIB,2*GIB,2*GIB)
    def test_shared_host_keeps_ten_gib_and_three_snapshot_sizes_free(self):
        with self.assertRaises(ValueError):check_budget(0,0,GIB,12*GIB,4*GIB,4*GIB)
    def test_local_accumulation_and_remote_budget_stop_new_backups(self):
        with self.assertRaises(ValueError):check_budget(2*GIB,0,10,20*GIB,2*GIB,2*GIB)
        with self.assertRaises(ValueError):check_budget(0,2*GIB,10,20*GIB,2*GIB,2*GIB)
if __name__=='__main__':unittest.main()
